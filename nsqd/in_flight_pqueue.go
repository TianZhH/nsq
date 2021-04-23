package nsqd

type inFlightPqueue []*Message

func newInFlightPqueue(capacity int) inFlightPqueue {
	return make(inFlightPqueue, 0, capacity)
}

func (pq inFlightPqueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].index = i
	pq[j].index = j
}

func (pq *inFlightPqueue) Push(x *Message) {
	n := len(*pq)
	c := cap(*pq)
	if n+1 > c {	// 扩容
		npq := make(inFlightPqueue, n, c*2)
		copy(npq, *pq)
		*pq = npq
	}
	*pq = (*pq)[0 : n+1]
	x.index = n
	(*pq)[n] = x
	pq.up(n)	// 将新 push 进来的元素放到最后 然后向上调整堆
}

func (pq *inFlightPqueue) Pop() *Message {	// 从堆中 pop 出堆顶元素
	n := len(*pq)
	c := cap(*pq)
	pq.Swap(0, n-1)	// 将堆顶与最后元素交换
	pq.down(0, n-1)	//	从根节点开始 向下调整堆
	if n < (c/2) && c > 25 {	// 堆缩容
		npq := make(inFlightPqueue, n, c/2)
		copy(npq, *pq)
		*pq = npq
	}
	x := (*pq)[n-1]
	x.index = -1
	*pq = (*pq)[0 : n-1]
	return x
}

func (pq *inFlightPqueue) Remove(i int) *Message {	// 删除某个节点
	n := len(*pq)
	if n-1 != i {
		pq.Swap(i, n-1)	// 将 被移除的 节点放到最后
		pq.down(i, n-1)	// 先向下调整 保证 i 这个位置满足最小堆
		pq.up(i)	// 然后再向上调整
	}
	x := (*pq)[n-1]	// 将最后一个移除
	x.index = -1
	*pq = (*pq)[0 : n-1]
	return x
}

func (pq *inFlightPqueue) PeekAndShift(max int64) (*Message, int64) {	// 如果堆顶消息的 pri > max 则 pop
	if len(*pq) == 0 {
		return nil, 0
	}

	x := (*pq)[0]
	if x.pri > max {
		return nil, x.pri - max
	}
	pq.Pop()

	return x, 0
}

func (pq *inFlightPqueue) up(j int) {	// 向上调整堆正确性
	for {
		i := (j - 1) / 2 // parent	// j 作为子节点找到 j 的父节点 i
		if i == j || (*pq)[j].pri >= (*pq)[i].pri {	// 如果 子节点 j 的 pri >= 父节点 i 的 pri 则无需交换，否则交换子节点和父节点 (交换之前父节点肯定是小于另一个子节点的，所以只关心j这个子节点和父节点i的大小关系)
			break
		}
		pq.Swap(i, j)
		j = i
	}
}

func (pq *inFlightPqueue) down(i, n int) {		// 向下调整堆的正确性
	for {
		j1 := 2*i + 1
		if j1 >= n || j1 < 0 { // j1 < 0 after int overflow
			break
		}
		j := j1 // left child	// j1 为 左子节点 j2 为右子节点  j 为 i 的左右子节点中 pri 最小的节点
		if j2 := j1 + 1; j2 < n && (*pq)[j1].pri >= (*pq)[j2].pri {		// 如果 j1.pri >= j2.pri 则 j=j2
			j = j2 // = 2*i + 2  // right child
		}
		if (*pq)[j].pri >= (*pq)[i].pri {	// 如果 i 的最小子节点的 pri >= i.pri 则不需要交换 否则 交换 i 和 j
			break
		}
		pq.Swap(i, j)
		i = j
	}
}
