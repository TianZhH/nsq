package nsqd

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/TianZhH/nsq/internal/protocol"
	"github.com/TianZhH/nsq/internal/version"
)

const maxTimeout = time.Hour

const (
	frameTypeResponse int32 = 0
	frameTypeError    int32 = 1
	frameTypeMessage  int32 = 2
)

var separatorBytes = []byte(" ")
var heartbeatBytes = []byte("_heartbeat_")
var okBytes = []byte("OK")

type protocolV2 struct {
	ctx *context
}

func (p *protocolV2) IOLoop(conn net.Conn) error {	// 循环处理网络事件
	var err error
	var line []byte
	var zeroTime time.Time

	clientID := atomic.AddInt64(&p.ctx.nsqd.clientIDSequence, 1)
	client := newClientV2(clientID, conn, p.ctx)	// 为
	p.ctx.nsqd.AddClient(client.ID, client)

	// synchronize the startup of messagePump in order
	// to guarantee that it gets a chance to initialize
	// goroutine local state derived from client attributes
	// and avoid a potential race with IDENTIFY (where a client
	// could have changed or disabled said attributes)
	messagePumpStartedChan := make(chan bool)	// 用来通知 messagePump 流程已初始化完毕 开始 pump 流程
	go p.messagePump(client, messagePumpStartedChan)
	<-messagePumpStartedChan

	for {
		if client.HeartbeatInterval > 0 {
			client.SetReadDeadline(time.Now().Add(client.HeartbeatInterval * 2))
		} else {
			client.SetReadDeadline(zeroTime)
		}

		// ReadSlice does not allocate new space for the data each request
		// ie. the returned slice is only valid until the next call to it
		line, err = client.Reader.ReadSlice('\n')	// 读取 客户端发送的第一行 一般为 client 发来的命令和参数
		if err != nil {
			if err == io.EOF {
				err = nil
			} else {
				err = fmt.Errorf("failed to read command - %s", err)
			}
			break
		}

		// trim the '\n'
		line = line[:len(line)-1]
		// optionally trim the '\r'
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		params := bytes.Split(line, separatorBytes)	// 解析第一行数据为多个参数

		p.ctx.nsqd.logf(LOG_DEBUG, "PROTOCOL(V2): [%s] %s", client, params)

		var response []byte
		response, err = p.Exec(client, params)	// 执行客户端命令
		if err != nil {
			ctx := ""
			if parentErr := err.(protocol.ChildErr).Parent(); parentErr != nil {
				ctx = " - " + parentErr.Error()
			}
			p.ctx.nsqd.logf(LOG_ERROR, "[%s] - %s%s", client, err, ctx)

			sendErr := p.Send(client, frameTypeError, []byte(err.Error()))
			if sendErr != nil {
				p.ctx.nsqd.logf(LOG_ERROR, "[%s] - %s%s", client, sendErr, ctx)
				break
			}

			// errors of type FatalClientErr should forceably close the connection
			if _, ok := err.(*protocol.FatalClientErr); ok {
				break
			}
			continue
		}

		if response != nil {
			err = p.Send(client, frameTypeResponse, response)
			if err != nil {
				err = fmt.Errorf("failed to send response - %s", err)
				break
			}
		}
	}

	p.ctx.nsqd.logf(LOG_INFO, "PROTOCOL(V2): [%s] exiting ioloop", client)
	conn.Close()
	close(client.ExitChan)
	if client.Channel != nil {
		client.Channel.RemoveClient(client.ID)
	}

	p.ctx.nsqd.RemoveClient(client.ID)
	return err
}

func (p *protocolV2) SendMessage(client *clientV2, msg *Message) error {
	p.ctx.nsqd.logf(LOG_DEBUG, "PROTOCOL(V2): writing msg(%s) to client(%s) - %s", msg.ID, client, msg.Body)
	var buf = &bytes.Buffer{}

	_, err := msg.WriteTo(buf)
	if err != nil {
		return err
	}

	err = p.Send(client, frameTypeMessage, buf.Bytes())
	if err != nil {
		return err
	}

	return nil
}

func (p *protocolV2) Send(client *clientV2, frameType int32, data []byte) error {
	client.writeLock.Lock()

	var zeroTime time.Time
	if client.HeartbeatInterval > 0 {
		client.SetWriteDeadline(time.Now().Add(client.HeartbeatInterval))
	} else {
		client.SetWriteDeadline(zeroTime)
	}

	_, err := protocol.SendFramedResponse(client.Writer, frameType, data)
	if err != nil {
		client.writeLock.Unlock()
		return err
	}

	if frameType != frameTypeMessage {
		err = client.Flush()
	}

	client.writeLock.Unlock()

	return err
}

func (p *protocolV2) Exec(client *clientV2, params [][]byte) ([]byte, error) {
	if bytes.Equal(params[0], []byte("IDENTIFY")) {
		return p.IDENTIFY(client, params)
	}
	err := enforceTLSPolicy(client, p, params[0])
	if err != nil {
		return nil, err
	}
	switch {
	case bytes.Equal(params[0], []byte("FIN")):
		return p.FIN(client, params)	// 将 message 从 in-flight 队列中移除
	case bytes.Equal(params[0], []byte("RDY")):
		return p.RDY(client, params)	// 设置 client.ReadyCount = RDY 命令指定的 count
	case bytes.Equal(params[0], []byte("REQ")):
		return p.REQ(client, params)	// 将 消息从 in-flight 队列取出，放到 deferred 队列中，并设置超时时间
	case bytes.Equal(params[0], []byte("PUB")):
		return p.PUB(client, params)	// 为消息生成唯一id，并写入到topic, topic chan 已满则写入磁盘，并更新 topic 的 msg 计数
	case bytes.Equal(params[0], []byte("MPUB")):
		return p.MPUB(client, params)	// 同上
	case bytes.Equal(params[0], []byte("DPUB")):
		return p.DPUB(client, params)
	case bytes.Equal(params[0], []byte("NOP")):
		return p.NOP(client, params)
	case bytes.Equal(params[0], []byte("TOUCH")):
		return p.TOUCH(client, params)	// 修改 if-flight msg 的过期时间，如果超过 nsq 配置的 max-timeout 则设置为 max-timeout
	case bytes.Equal(params[0], []byte("SUB")):
		return p.SUB(client, params)	// 创建 topic、channel, 将 client 添加到 channel.clients(map类型), 并检测订阅该 channel 的 client 超过最大值，最终 client.Channel,client.SubEventChan 指向 该 channel
	case bytes.Equal(params[0], []byte("CLS")):
		return p.CLS(client, params)	// 修改 client.State = CLOSE, client.ReadyCount = 0 ReadyCount > 0 表示 client 已准备好接收消息
	case bytes.Equal(params[0], []byte("AUTH")):
		return p.AUTH(client, params)
	}
	return nil, protocol.NewFatalClientErr(nil, "E_INVALID", fmt.Sprintf("invalid command %s", params[0]))
}

func (p *protocolV2) messagePump(client *clientV2, startedChan chan bool) {// 消费 client 订阅的 channel 的 memoryMsgChan 和 backendMsgChan， 发送给 client
	var err error
	var memoryMsgChan chan *Message
	var backendMsgChan <-chan []byte
	var subChannel *Channel
	// NOTE: `flusherChan` is used to bound message latency for
	// the pathological case of a channel on a low volume topic
	// with >1 clients having >1 RDY counts
	var flusherChan <-chan time.Time
	var sampleRate int32

	subEventChan := client.SubEventChan		// 在 protocolV2.Exec() 方法中处理 SUB 指令时，可知 SubEventChan 指向的是 该 client 订阅的 channel
	identifyEventChan := client.IdentifyEventChan		// 在 protocolV2.Exec() 方法中处理 IDENTIFY 指令时，可知 IDENTIFY 处理时会将新的 client 元信息投递到此 chan
	outputBufferTicker := time.NewTicker(client.OutputBufferTimeout)	// IDENTIFY 指令会更新此值，否则使用nsq配置( nsqd.getOpts().OutputBufferTimeout)  nsqd 发送消息到 client 的超时时间
	heartbeatTicker := time.NewTicker(client.HeartbeatInterval)	// 同上
	heartbeatChan := heartbeatTicker.C
	msgTimeout := client.MsgTimeout		// 同 heartbeat 配置

	// v2 opportunistically buffers data to clients to reduce write system calls
	// we force flush in two cases:
	//    1. when the client is not ready to receive messages
	//    2. we're buffered and the channel has nothing left to send us
	//       (ie. we would block in this loop anyway)
	//
	flushed := true

	// signal to the goroutine that started the messagePump
	// that we've started up
	close(startedChan)	// 通知外层，pump 准备完毕

	for {
		if subChannel == nil || !client.IsReadyForMessages() {	// 如果 client 没有订阅 channel，或者 client 没准备好接受 msg（client 发送 CLS 指令），则将写缓存的缓存数据发送到 client(flush writer)
			// the client is not ready to receive messages...
			memoryMsgChan = nil
			backendMsgChan = nil
			flusherChan = nil
			// force flush
			client.writeLock.Lock()
			err = client.Flush()
			client.writeLock.Unlock()
			if err != nil {
				goto exit
			}
			flushed = true
		} else if flushed {
			// last iteration we flushed...
			// do not select on the flusher ticker channel
			memoryMsgChan = subChannel.memoryMsgChan
			backendMsgChan = subChannel.backend.ReadChan()
			flusherChan = nil
		} else {
			// we're buffered (if there isn't any more data we should flush)...
			// select on the flusher ticker channel, too
			memoryMsgChan = subChannel.memoryMsgChan
			backendMsgChan = subChannel.backend.ReadChan()
			flusherChan = outputBufferTicker.C
		}

		select {
		case <-flusherChan:	// 到达 flush 超时时间 则刷新
			// if this case wins, we're either starved
			// or we won the race between other channels...
			// in either case, force flush
			client.writeLock.Lock()
			err = client.Flush()
			client.writeLock.Unlock()
			if err != nil {
				goto exit
			}
			flushed = true
		case <-client.ReadyStateChan:	// TODO
		case subChannel = <-subEventChan:	// pump 只处理 client 第一次订阅的 channel，不再关心 subEventChan(client 只应该订阅一个 channel，client 在其他地方做了限制，pump 同样做了限制)
			// you can't SUB anymore
			subEventChan = nil
		case identifyData := <-identifyEventChan:	// pump 只处理 client 第一次发来的 IDENTIFY 指令
			// you can't IDENTIFY anymore
			identifyEventChan = nil

			outputBufferTicker.Stop()
			if identifyData.OutputBufferTimeout > 0 {
				outputBufferTicker = time.NewTicker(identifyData.OutputBufferTimeout)
			}

			heartbeatTicker.Stop()
			heartbeatChan = nil
			if identifyData.HeartbeatInterval > 0 {
				heartbeatTicker = time.NewTicker(identifyData.HeartbeatInterval)
				heartbeatChan = heartbeatTicker.C
			}

			if identifyData.SampleRate > 0 {
				sampleRate = identifyData.SampleRate
			}

			msgTimeout = identifyData.MsgTimeout
		case <-heartbeatChan:	// 发送心跳消息
			err = p.Send(client, frameTypeResponse, heartbeatBytes)
			if err != nil {
				goto exit
			}
		case b := <-backendMsgChan:	// 处理磁盘消息
			if sampleRate > 0 && rand.Int31n(100) > sampleRate {
				continue
			}

			msg, err := decodeMessage(b)
			if err != nil {
				p.ctx.nsqd.logf(LOG_ERROR, "failed to decode message - %s", err)
				continue
			}
			msg.Attempts++

			subChannel.StartInFlightTimeout(msg, client.ID, msgTimeout)	// 将消息放到 in-flight 队列中
			client.SendingMessage()	// 更新已发送 msg 的计数
			err = p.SendMessage(client, msg)	// 真正发送消息给 client
			if err != nil {
				goto exit
			}
			flushed = false
		case msg := <-memoryMsgChan:	// 处理内存消息
			if sampleRate > 0 && rand.Int31n(100) > sampleRate {	// TODO
				continue
			}
			msg.Attempts++

			subChannel.StartInFlightTimeout(msg, client.ID, msgTimeout)	// 将消息放到 in-flight 队列中
			client.SendingMessage()	// 更新已发送 msg 的计数
			err = p.SendMessage(client, msg)	// 真正发送消息给 client
			if err != nil {
				goto exit
			}
			flushed = false
		case <-client.ExitChan:
			goto exit
		}
	}

exit:
	p.ctx.nsqd.logf(LOG_INFO, "PROTOCOL(V2): [%s] exiting messagePump", client)
	heartbeatTicker.Stop()		// 释放  ticker 资源
	outputBufferTicker.Stop() 	// 释放  ticker 资源
	if err != nil {
		p.ctx.nsqd.logf(LOG_ERROR, "PROTOCOL(V2): [%s] messagePump error - %s", client, err)
	}
}

func (p *protocolV2) IDENTIFY(client *clientV2, params [][]byte) ([]byte, error) {	// 参考官方文档 https://nsq.io/clients/tcp_protocol_spec.html#identify
	var err error

	if atomic.LoadInt32(&client.State) != stateInit {	// 初始化状态才能进行 IDENTIFY 操作
		return nil, protocol.NewFatalClientErr(nil, "E_INVALID", "cannot IDENTIFY in current state")
	}

	bodyLen, err := readLen(client.Reader, client.lenSlice) // IDENTIFY\n [ 4-byte size in bytes ][ N-byte JSON data ]  前面已经读取了\n之前的 IDENTIFY 命令， 这里读取的是\n后面标识 body 长度 4 字节数据
	if err != nil {
		return nil, protocol.NewFatalClientErr(err, "E_BAD_BODY", "IDENTIFY failed to read body size")
	}

	if int64(bodyLen) > p.ctx.nsqd.getOpts().MaxBodySize {
		return nil, protocol.NewFatalClientErr(nil, "E_BAD_BODY",
			fmt.Sprintf("IDENTIFY body too big %d > %d", bodyLen, p.ctx.nsqd.getOpts().MaxBodySize))
	}

	if bodyLen <= 0 {
		return nil, protocol.NewFatalClientErr(nil, "E_BAD_BODY",
			fmt.Sprintf("IDENTIFY invalid body size %d", bodyLen))
	}

	body := make([]byte, bodyLen)
	_, err = io.ReadFull(client.Reader, body)	// 按照协议制定的 body 长度，读取 body 数据
	if err != nil {
		return nil, protocol.NewFatalClientErr(err, "E_BAD_BODY", "IDENTIFY failed to read body")
	}

	// body is a json structure with producer information
	var identifyData identifyDataV2
	err = json.Unmarshal(body, &identifyData) // 解析 body
	if err != nil {
		return nil, protocol.NewFatalClientErr(err, "E_BAD_BODY", "IDENTIFY failed to decode JSON body")
	}

	p.ctx.nsqd.logf(LOG_DEBUG, "PROTOCOL(V2): [%s] %+v", client, identifyData)

	err = client.Identify(identifyData)	// 更新 client 元数据
	if err != nil {
		return nil, protocol.NewFatalClientErr(err, "E_BAD_BODY", "IDENTIFY "+err.Error())
	}

	// bail out early if we're not negotiating features
	if !identifyData.FeatureNegotiation {	// 客户端不支持协商功能，直接返回
		return okBytes, nil
	}

	tlsv1 := p.ctx.nsqd.tlsConfig != nil && identifyData.TLSv1	// 如果 nsq 支持 tls 且 客户端启用tls， 则 tlsv1 = true
	deflate := p.ctx.nsqd.getOpts().DeflateEnabled && identifyData.Deflate	// 如果 nsq 支持压缩 且 客户端启用此功能，则 deflate = true
	deflateLevel := 6	// 压缩等级优先级: 本地配置的最大等级 > 客户端指定压缩等级 > 默认等级
	if deflate && identifyData.DeflateLevel > 0 {
		deflateLevel = identifyData.DeflateLevel
	}
	if max := p.ctx.nsqd.getOpts().MaxDeflateLevel; max < deflateLevel {
		deflateLevel = max
	}
	snappy := p.ctx.nsqd.getOpts().SnappyEnabled && identifyData.Snappy	// 如果 nsq 支持快照压缩 且 客户端启用此功能， 则 snappy = true

	if deflate && snappy {	// 不能同时启用快照压缩和 deflate 压缩
		return nil, protocol.NewFatalClientErr(nil, "E_IDENTIFY_FAILED", "cannot enable both deflate and snappy compression")
	}

	resp, err := json.Marshal(struct {		// 封装协商之后的数据
		MaxRdyCount         int64  `json:"max_rdy_count"`
		Version             string `json:"version"`
		MaxMsgTimeout       int64  `json:"max_msg_timeout"`
		MsgTimeout          int64  `json:"msg_timeout"`
		TLSv1               bool   `json:"tls_v1"`
		Deflate             bool   `json:"deflate"`
		DeflateLevel        int    `json:"deflate_level"`
		MaxDeflateLevel     int    `json:"max_deflate_level"`
		Snappy              bool   `json:"snappy"`
		SampleRate          int32  `json:"sample_rate"`
		AuthRequired        bool   `json:"auth_required"`
		OutputBufferSize    int    `json:"output_buffer_size"`
		OutputBufferTimeout int64  `json:"output_buffer_timeout"`
	}{
		MaxRdyCount:         p.ctx.nsqd.getOpts().MaxRdyCount,
		Version:             version.Binary,
		MaxMsgTimeout:       int64(p.ctx.nsqd.getOpts().MaxMsgTimeout / time.Millisecond),
		MsgTimeout:          int64(client.MsgTimeout / time.Millisecond),
		TLSv1:               tlsv1,
		Deflate:             deflate,
		DeflateLevel:        deflateLevel,
		MaxDeflateLevel:     p.ctx.nsqd.getOpts().MaxDeflateLevel,
		Snappy:              snappy,
		SampleRate:          client.SampleRate,
		AuthRequired:        p.ctx.nsqd.IsAuthEnabled(),
		OutputBufferSize:    client.OutputBufferSize,
		OutputBufferTimeout: int64(client.OutputBufferTimeout / time.Millisecond),
	})
	if err != nil {
		return nil, protocol.NewFatalClientErr(err, "E_IDENTIFY_FAILED", "IDENTIFY failed "+err.Error())
	}

	err = p.Send(client, frameTypeResponse, resp)
	if err != nil {
		return nil, protocol.NewFatalClientErr(err, "E_IDENTIFY_FAILED", "IDENTIFY failed "+err.Error())
	}

	if tlsv1 {		// 将 client conn 封装为 tls conn
		p.ctx.nsqd.logf(LOG_INFO, "PROTOCOL(V2): [%s] upgrading connection to TLS", client)
		err = client.UpgradeTLS()
		if err != nil {
			return nil, protocol.NewFatalClientErr(err, "E_IDENTIFY_FAILED", "IDENTIFY failed "+err.Error())
		}

		err = p.Send(client, frameTypeResponse, okBytes)
		if err != nil {
			return nil, protocol.NewFatalClientErr(err, "E_IDENTIFY_FAILED", "IDENTIFY failed "+err.Error())
		}
	}

	if snappy {		// 将 client conn 封装为 snappy conn
		p.ctx.nsqd.logf(LOG_INFO, "PROTOCOL(V2): [%s] upgrading connection to snappy", client)
		err = client.UpgradeSnappy()
		if err != nil {
			return nil, protocol.NewFatalClientErr(err, "E_IDENTIFY_FAILED", "IDENTIFY failed "+err.Error())
		}

		err = p.Send(client, frameTypeResponse, okBytes)
		if err != nil {
			return nil, protocol.NewFatalClientErr(err, "E_IDENTIFY_FAILED", "IDENTIFY failed "+err.Error())
		}
	}

	if deflate {	// 将 client conn 封装为 deflate conn
		p.ctx.nsqd.logf(LOG_INFO, "PROTOCOL(V2): [%s] upgrading connection to deflate (level %d)", client, deflateLevel)
		err = client.UpgradeDeflate(deflateLevel)
		if err != nil {
			return nil, protocol.NewFatalClientErr(err, "E_IDENTIFY_FAILED", "IDENTIFY failed "+err.Error())
		}

		err = p.Send(client, frameTypeResponse, okBytes)
		if err != nil {
			return nil, protocol.NewFatalClientErr(err, "E_IDENTIFY_FAILED", "IDENTIFY failed "+err.Error())
		}
	}

	return nil, nil
}

func (p *protocolV2) AUTH(client *clientV2, params [][]byte) ([]byte, error) {
	if atomic.LoadInt32(&client.State) != stateInit {
		return nil, protocol.NewFatalClientErr(nil, "E_INVALID", "cannot AUTH in current state")
	}

	if len(params) != 1 {
		return nil, protocol.NewFatalClientErr(nil, "E_INVALID", "AUTH invalid number of parameters")
	}

	bodyLen, err := readLen(client.Reader, client.lenSlice)
	if err != nil {
		return nil, protocol.NewFatalClientErr(err, "E_BAD_BODY", "AUTH failed to read body size")
	}

	if int64(bodyLen) > p.ctx.nsqd.getOpts().MaxBodySize {
		return nil, protocol.NewFatalClientErr(nil, "E_BAD_BODY",
			fmt.Sprintf("AUTH body too big %d > %d", bodyLen, p.ctx.nsqd.getOpts().MaxBodySize))
	}

	if bodyLen <= 0 {
		return nil, protocol.NewFatalClientErr(nil, "E_BAD_BODY",
			fmt.Sprintf("AUTH invalid body size %d", bodyLen))
	}

	body := make([]byte, bodyLen)
	_, err = io.ReadFull(client.Reader, body)
	if err != nil {
		return nil, protocol.NewFatalClientErr(err, "E_BAD_BODY", "AUTH failed to read body")
	}

	if client.HasAuthorizations() {
		return nil, protocol.NewFatalClientErr(nil, "E_INVALID", "AUTH already set")
	}

	if !client.ctx.nsqd.IsAuthEnabled() {
		return nil, protocol.NewFatalClientErr(err, "E_AUTH_DISABLED", "AUTH disabled")
	}

	if err := client.Auth(string(body)); err != nil {
		// we don't want to leak errors contacting the auth server to untrusted clients
		p.ctx.nsqd.logf(LOG_WARN, "PROTOCOL(V2): [%s] AUTH failed %s", client, err)
		return nil, protocol.NewFatalClientErr(err, "E_AUTH_FAILED", "AUTH failed")
	}

	if !client.HasAuthorizations() {
		return nil, protocol.NewFatalClientErr(nil, "E_UNAUTHORIZED", "AUTH no authorizations found")
	}

	resp, err := json.Marshal(struct {
		Identity        string `json:"identity"`
		IdentityURL     string `json:"identity_url"`
		PermissionCount int    `json:"permission_count"`
	}{
		Identity:        client.AuthState.Identity,
		IdentityURL:     client.AuthState.IdentityURL,
		PermissionCount: len(client.AuthState.Authorizations),
	})
	if err != nil {
		return nil, protocol.NewFatalClientErr(err, "E_AUTH_ERROR", "AUTH error "+err.Error())
	}

	err = p.Send(client, frameTypeResponse, resp)
	if err != nil {
		return nil, protocol.NewFatalClientErr(err, "E_AUTH_ERROR", "AUTH error "+err.Error())
	}

	return nil, nil

}

func (p *protocolV2) CheckAuth(client *clientV2, cmd, topicName, channelName string) error {
	// if auth is enabled, the client must have authorized already
	// compare topic/channel against cached authorization data (refetching if expired)
	if client.ctx.nsqd.IsAuthEnabled() {
		if !client.HasAuthorizations() {
			return protocol.NewFatalClientErr(nil, "E_AUTH_FIRST",
				fmt.Sprintf("AUTH required before %s", cmd))
		}
		ok, err := client.IsAuthorized(topicName, channelName)
		if err != nil {
			// we don't want to leak errors contacting the auth server to untrusted clients
			p.ctx.nsqd.logf(LOG_WARN, "PROTOCOL(V2): [%s] AUTH failed %s", client, err)
			return protocol.NewFatalClientErr(nil, "E_AUTH_FAILED", "AUTH failed")
		}
		if !ok {
			return protocol.NewFatalClientErr(nil, "E_UNAUTHORIZED",
				fmt.Sprintf("AUTH failed for %s on %q %q", cmd, topicName, channelName))
		}
	}
	return nil
}

func (p *protocolV2) SUB(client *clientV2, params [][]byte) ([]byte, error) {
	if atomic.LoadInt32(&client.State) != stateInit {
		return nil, protocol.NewFatalClientErr(nil, "E_INVALID", "cannot SUB in current state")
	}

	if client.HeartbeatInterval <= 0 {
		return nil, protocol.NewFatalClientErr(nil, "E_INVALID", "cannot SUB with heartbeats disabled")
	}

	if len(params) < 3 {
		return nil, protocol.NewFatalClientErr(nil, "E_INVALID", "SUB insufficient number of parameters")
	}

	topicName := string(params[1])
	if !protocol.IsValidTopicName(topicName) {
		return nil, protocol.NewFatalClientErr(nil, "E_BAD_TOPIC",
			fmt.Sprintf("SUB topic name %q is not valid", topicName))
	}

	channelName := string(params[2])
	if !protocol.IsValidChannelName(channelName) {
		return nil, protocol.NewFatalClientErr(nil, "E_BAD_CHANNEL",
			fmt.Sprintf("SUB channel name %q is not valid", channelName))
	}

	if err := p.CheckAuth(client, "SUB", topicName, channelName); err != nil {
		return nil, err
	}

	// This retry-loop is a work-around for a race condition, where the
	// last client can leave the channel between GetChannel() and AddClient().
	// Avoid adding a client to an ephemeral channel / topic which has started exiting.
	var channel *Channel
	for {
		topic := p.ctx.nsqd.GetTopic(topicName)
		channel = topic.GetChannel(channelName)
		if err := channel.AddClient(client.ID, client); err != nil {
			return nil, protocol.NewFatalClientErr(nil, "E_TOO_MANY_CHANNEL_CONSUMERS",
				fmt.Sprintf("channel consumers for %s:%s exceeds limit of %d",
					topicName, channelName, p.ctx.nsqd.getOpts().MaxChannelConsumers))
		}

		if (channel.ephemeral && channel.Exiting()) || (topic.ephemeral && topic.Exiting()) {
			channel.RemoveClient(client.ID)
			time.Sleep(1 * time.Millisecond)
			continue
		}
		break
	}
	atomic.StoreInt32(&client.State, stateSubscribed)
	client.Channel = channel
	// update message pump
	client.SubEventChan <- channel

	return okBytes, nil
}

func (p *protocolV2) RDY(client *clientV2, params [][]byte) ([]byte, error) {
	state := atomic.LoadInt32(&client.State)

	if state == stateClosing {
		// just ignore ready changes on a closing channel
		p.ctx.nsqd.logf(LOG_INFO,
			"PROTOCOL(V2): [%s] ignoring RDY after CLS in state ClientStateV2Closing",
			client)
		return nil, nil
	}

	if state != stateSubscribed {
		return nil, protocol.NewFatalClientErr(nil, "E_INVALID", "cannot RDY in current state")
	}

	count := int64(1)
	if len(params) > 1 {
		b10, err := protocol.ByteToBase10(params[1])
		if err != nil {
			return nil, protocol.NewFatalClientErr(err, "E_INVALID",
				fmt.Sprintf("RDY could not parse count %s", params[1]))
		}
		count = int64(b10)
	}

	if count < 0 || count > p.ctx.nsqd.getOpts().MaxRdyCount {
		// this needs to be a fatal error otherwise clients would have
		// inconsistent state
		return nil, protocol.NewFatalClientErr(nil, "E_INVALID",
			fmt.Sprintf("RDY count %d out of range 0-%d", count, p.ctx.nsqd.getOpts().MaxRdyCount))
	}

	client.SetReadyCount(count)

	return nil, nil
}

func (p *protocolV2) FIN(client *clientV2, params [][]byte) ([]byte, error) {
	state := atomic.LoadInt32(&client.State)
	if state != stateSubscribed && state != stateClosing {
		return nil, protocol.NewFatalClientErr(nil, "E_INVALID", "cannot FIN in current state")
	}

	if len(params) < 2 {
		return nil, protocol.NewFatalClientErr(nil, "E_INVALID", "FIN insufficient number of params")
	}

	id, err := getMessageID(params[1])
	if err != nil {
		return nil, protocol.NewFatalClientErr(nil, "E_INVALID", err.Error())
	}

	err = client.Channel.FinishMessage(client.ID, *id)	// 将 message 从 in-flight 队列中移除
	if err != nil {
		return nil, protocol.NewClientErr(err, "E_FIN_FAILED",
			fmt.Sprintf("FIN %s failed %s", *id, err.Error()))
	}

	client.FinishedMessage()

	return nil, nil
}

func (p *protocolV2) REQ(client *clientV2, params [][]byte) ([]byte, error) {
	state := atomic.LoadInt32(&client.State)
	if state != stateSubscribed && state != stateClosing {
		return nil, protocol.NewFatalClientErr(nil, "E_INVALID", "cannot REQ in current state")
	}

	if len(params) < 3 {
		return nil, protocol.NewFatalClientErr(nil, "E_INVALID", "REQ insufficient number of params")
	}

	id, err := getMessageID(params[1])
	if err != nil {
		return nil, protocol.NewFatalClientErr(nil, "E_INVALID", err.Error())
	}

	timeoutMs, err := protocol.ByteToBase10(params[2])
	if err != nil {
		return nil, protocol.NewFatalClientErr(err, "E_INVALID",
			fmt.Sprintf("REQ could not parse timeout %s", params[2]))
	}
	timeoutDuration := time.Duration(timeoutMs) * time.Millisecond

	maxReqTimeout := p.ctx.nsqd.getOpts().MaxReqTimeout
	clampedTimeout := timeoutDuration
	// 校验指定的超时时间
	if timeoutDuration < 0 {
		clampedTimeout = 0
	} else if timeoutDuration > maxReqTimeout {
		clampedTimeout = maxReqTimeout
	}
	if clampedTimeout != timeoutDuration {
		p.ctx.nsqd.logf(LOG_INFO, "PROTOCOL(V2): [%s] REQ timeout %d out of range 0-%d. Setting to %d",
			client, timeoutDuration, maxReqTimeout, clampedTimeout)
		timeoutDuration = clampedTimeout
	}

	err = client.Channel.RequeueMessage(client.ID, *id, timeoutDuration)	// 将 消息从 in-flight 队列取出，放到 deferred 队列中，并设置超时时间
	if err != nil {
		return nil, protocol.NewClientErr(err, "E_REQ_FAILED",
			fmt.Sprintf("REQ %s failed %s", *id, err.Error()))
	}

	client.RequeuedMessage()

	return nil, nil
}

func (p *protocolV2) CLS(client *clientV2, params [][]byte) ([]byte, error) {
	if atomic.LoadInt32(&client.State) != stateSubscribed {
		return nil, protocol.NewFatalClientErr(nil, "E_INVALID", "cannot CLS in current state")
	}

	client.StartClose()

	return []byte("CLOSE_WAIT"), nil
}

func (p *protocolV2) NOP(client *clientV2, params [][]byte) ([]byte, error) {
	return nil, nil
}

func (p *protocolV2) PUB(client *clientV2, params [][]byte) ([]byte, error) {	// 协议地址 https://nsq.io/clients/tcp_protocol_spec.html#identify
	var err error

	if len(params) < 2 {
		return nil, protocol.NewFatalClientErr(nil, "E_INVALID", "PUB insufficient number of parameters")
	}

	topicName := string(params[1])
	if !protocol.IsValidTopicName(topicName) {	// topic name 是否合法
		return nil, protocol.NewFatalClientErr(nil, "E_BAD_TOPIC",
			fmt.Sprintf("PUB topic name %q is not valid", topicName))
	}

	bodyLen, err := readLen(client.Reader, client.lenSlice)	// 取出 body-len  协议:PUB <topic_name>\n[ 4-byte size in bytes ][ N-byte binary data ]
	if err != nil {
		return nil, protocol.NewFatalClientErr(err, "E_BAD_MESSAGE", "PUB failed to read message body size")
	}

	if bodyLen <= 0 {
		return nil, protocol.NewFatalClientErr(nil, "E_BAD_MESSAGE",
			fmt.Sprintf("PUB invalid message body size %d", bodyLen))
	}

	if int64(bodyLen) > p.ctx.nsqd.getOpts().MaxMsgSize {
		return nil, protocol.NewFatalClientErr(nil, "E_BAD_MESSAGE",
			fmt.Sprintf("PUB message too big %d > %d", bodyLen, p.ctx.nsqd.getOpts().MaxMsgSize))
	}

	messageBody := make([]byte, bodyLen)	// 取出 message
	_, err = io.ReadFull(client.Reader, messageBody)
	if err != nil {
		return nil, protocol.NewFatalClientErr(err, "E_BAD_MESSAGE", "PUB failed to read message body")
	}

	if err := p.CheckAuth(client, "PUB", topicName, ""); err != nil {
		return nil, err
	}

	topic := p.ctx.nsqd.GetTopic(topicName)
	msg := NewMessage(topic.GenerateID(), messageBody)	// 为 message 生成一个唯一 id
	err = topic.PutMessage(msg)	// 将 msg put 到 topic 里，内存满则写入到磁盘
	if err != nil {
		return nil, protocol.NewFatalClientErr(err, "E_PUB_FAILED", "PUB failed "+err.Error())
	}

	client.PublishedMessage(topicName, 1)		// 更新 topic 已发布的 msg 的计数

	return okBytes, nil
}

func (p *protocolV2) MPUB(client *clientV2, params [][]byte) ([]byte, error) {
	var err error

	if len(params) < 2 {
		return nil, protocol.NewFatalClientErr(nil, "E_INVALID", "MPUB insufficient number of parameters")
	}

	topicName := string(params[1])
	if !protocol.IsValidTopicName(topicName) {	// topic name 是否合法
		return nil, protocol.NewFatalClientErr(nil, "E_BAD_TOPIC",
			fmt.Sprintf("E_BAD_TOPIC MPUB topic name %q is not valid", topicName))
	}

	if err := p.CheckAuth(client, "MPUB", topicName, ""); err != nil {
		return nil, err
	}

	topic := p.ctx.nsqd.GetTopic(topicName)	// 获取 topic 没有则创建

	bodyLen, err := readLen(client.Reader, client.lenSlice)	// 获取 body len
	if err != nil {
		return nil, protocol.NewFatalClientErr(err, "E_BAD_BODY", "MPUB failed to read body size")
	}

	if bodyLen <= 0 {
		return nil, protocol.NewFatalClientErr(nil, "E_BAD_BODY",
			fmt.Sprintf("MPUB invalid body size %d", bodyLen))
	}

	if int64(bodyLen) > p.ctx.nsqd.getOpts().MaxBodySize {
		return nil, protocol.NewFatalClientErr(nil, "E_BAD_BODY",
			fmt.Sprintf("MPUB body too big %d > %d", bodyLen, p.ctx.nsqd.getOpts().MaxBodySize))
	}

	messages, err := readMPUB(client.Reader, client.lenSlice, topic,
		p.ctx.nsqd.getOpts().MaxMsgSize, p.ctx.nsqd.getOpts().MaxBodySize)	// 读取 messages
	if err != nil {
		return nil, err
	}

	// if we've made it this far we've validated all the input,
	// the only possible error is that the topic is exiting during
	// this next call (and no messages will be queued in that case)
	err = topic.PutMessages(messages)	// 将 msgs 写入内存，内存不足写入磁盘  如果中途写入发生错误 则前面写入的仍然生效(messageCount,messageBytes)，后面不再写入
	if err != nil {
		return nil, protocol.NewFatalClientErr(err, "E_MPUB_FAILED", "MPUB failed "+err.Error())
	}

	client.PublishedMessage(topicName, uint64(len(messages)))	// 更新 topic 的 msg 计数

	return okBytes, nil
}

func (p *protocolV2) DPUB(client *clientV2, params [][]byte) ([]byte, error) {
	var err error

	if len(params) < 3 {
		return nil, protocol.NewFatalClientErr(nil, "E_INVALID", "DPUB insufficient number of parameters")
	}

	topicName := string(params[1])
	if !protocol.IsValidTopicName(topicName) {
		return nil, protocol.NewFatalClientErr(nil, "E_BAD_TOPIC",
			fmt.Sprintf("DPUB topic name %q is not valid", topicName))
	}

	timeoutMs, err := protocol.ByteToBase10(params[2])
	if err != nil {
		return nil, protocol.NewFatalClientErr(err, "E_INVALID",
			fmt.Sprintf("DPUB could not parse timeout %s", params[2]))
	}
	timeoutDuration := time.Duration(timeoutMs) * time.Millisecond

	if timeoutDuration < 0 || timeoutDuration > p.ctx.nsqd.getOpts().MaxReqTimeout {
		return nil, protocol.NewFatalClientErr(nil, "E_INVALID",
			fmt.Sprintf("DPUB timeout %d out of range 0-%d",
				timeoutMs, p.ctx.nsqd.getOpts().MaxReqTimeout/time.Millisecond))
	}

	bodyLen, err := readLen(client.Reader, client.lenSlice)
	if err != nil {
		return nil, protocol.NewFatalClientErr(err, "E_BAD_MESSAGE", "DPUB failed to read message body size")
	}

	if bodyLen <= 0 {
		return nil, protocol.NewFatalClientErr(nil, "E_BAD_MESSAGE",
			fmt.Sprintf("DPUB invalid message body size %d", bodyLen))
	}

	if int64(bodyLen) > p.ctx.nsqd.getOpts().MaxMsgSize {
		return nil, protocol.NewFatalClientErr(nil, "E_BAD_MESSAGE",
			fmt.Sprintf("DPUB message too big %d > %d", bodyLen, p.ctx.nsqd.getOpts().MaxMsgSize))
	}

	messageBody := make([]byte, bodyLen)
	_, err = io.ReadFull(client.Reader, messageBody)
	if err != nil {
		return nil, protocol.NewFatalClientErr(err, "E_BAD_MESSAGE", "DPUB failed to read message body")
	}

	if err := p.CheckAuth(client, "DPUB", topicName, ""); err != nil {
		return nil, err
	}

	topic := p.ctx.nsqd.GetTopic(topicName)
	msg := NewMessage(topic.GenerateID(), messageBody)
	msg.deferred = timeoutDuration
	err = topic.PutMessage(msg)
	if err != nil {
		return nil, protocol.NewFatalClientErr(err, "E_DPUB_FAILED", "DPUB failed "+err.Error())
	}

	client.PublishedMessage(topicName, 1)

	return okBytes, nil
}

func (p *protocolV2) TOUCH(client *clientV2, params [][]byte) ([]byte, error) {
	state := atomic.LoadInt32(&client.State)
	if state != stateSubscribed && state != stateClosing {
		return nil, protocol.NewFatalClientErr(nil, "E_INVALID", "cannot TOUCH in current state")
	}

	if len(params) < 2 {
		return nil, protocol.NewFatalClientErr(nil, "E_INVALID", "TOUCH insufficient number of params")
	}

	id, err := getMessageID(params[1])
	if err != nil {
		return nil, protocol.NewFatalClientErr(nil, "E_INVALID", err.Error())
	}

	client.writeLock.RLock()
	msgTimeout := client.MsgTimeout
	client.writeLock.RUnlock()
	err = client.Channel.TouchMessage(client.ID, *id, msgTimeout)
	if err != nil {
		return nil, protocol.NewClientErr(err, "E_TOUCH_FAILED",
			fmt.Sprintf("TOUCH %s failed %s", *id, err.Error()))
	}

	return nil, nil
}

func readMPUB(r io.Reader, tmp []byte, topic *Topic, maxMessageSize int64, maxBodySize int64) ([]*Message, error) {
	numMessages, err := readLen(r, tmp)
	if err != nil {
		return nil, protocol.NewFatalClientErr(err, "E_BAD_BODY", "MPUB failed to read message count")
	}

	// 4 == total num, 5 == length + min 1
	maxMessages := (maxBodySize - 4) / 5
	if numMessages <= 0 || int64(numMessages) > maxMessages {
		return nil, protocol.NewFatalClientErr(err, "E_BAD_BODY",
			fmt.Sprintf("MPUB invalid message count %d", numMessages))
	}

	messages := make([]*Message, 0, numMessages)
	for i := int32(0); i < numMessages; i++ {
		messageSize, err := readLen(r, tmp)
		if err != nil {
			return nil, protocol.NewFatalClientErr(err, "E_BAD_MESSAGE",
				fmt.Sprintf("MPUB failed to read message(%d) body size", i))
		}

		if messageSize <= 0 {
			return nil, protocol.NewFatalClientErr(nil, "E_BAD_MESSAGE",
				fmt.Sprintf("MPUB invalid message(%d) body size %d", i, messageSize))
		}

		if int64(messageSize) > maxMessageSize {
			return nil, protocol.NewFatalClientErr(nil, "E_BAD_MESSAGE",
				fmt.Sprintf("MPUB message too big %d > %d", messageSize, maxMessageSize))
		}

		msgBody := make([]byte, messageSize)
		_, err = io.ReadFull(r, msgBody)
		if err != nil {
			return nil, protocol.NewFatalClientErr(err, "E_BAD_MESSAGE", "MPUB failed to read message body")
		}

		messages = append(messages, NewMessage(topic.GenerateID(), msgBody))
	}

	return messages, nil
}

// validate and cast the bytes on the wire to a message ID
func getMessageID(p []byte) (*MessageID, error) {
	if len(p) != MsgIDLength {
		return nil, errors.New("Invalid Message ID")
	}
	return (*MessageID)(unsafe.Pointer(&p[0])), nil
}

func readLen(r io.Reader, tmp []byte) (int32, error) {
	_, err := io.ReadFull(r, tmp)
	if err != nil {
		return 0, err
	}
	return int32(binary.BigEndian.Uint32(tmp)), nil
}

func enforceTLSPolicy(client *clientV2, p *protocolV2, command []byte) error {
	if p.ctx.nsqd.getOpts().TLSRequired != TLSNotRequired && atomic.LoadInt32(&client.TLS) != 1 {
		return protocol.NewFatalClientErr(nil, "E_INVALID",
			fmt.Sprintf("cannot %s in current state (TLS required)", command))
	}
	return nil
}
