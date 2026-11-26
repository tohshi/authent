package rebac

import (
	"container/list"
	"sync"
)

type checkCache struct {
	mu    sync.Mutex
	size  int
	order list.List // of *cached, most recently used first
	items map[CheckItem]*list.Element
}

type cached struct {
	item    CheckItem
	rev     Revision
	allowed bool
}

func newCheckCache(size int) *checkCache {
	return &checkCache{size: size, items: map[CheckItem]*list.Element{}}
}

func (c *checkCache) get(it CheckItem, min Revision) (allowed, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[it]
	if !ok || el.Value.(*cached).rev < min {
		return false, false
	}
	c.order.MoveToFront(el)
	return el.Value.(*cached).allowed, true
}

func (c *checkCache) put(it CheckItem, rev Revision, allowed bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[it]; ok {
		if e := el.Value.(*cached); e.rev < rev {
			e.rev, e.allowed = rev, allowed
		}
		c.order.MoveToFront(el)
		return
	}
	c.items[it] = c.order.PushFront(&cached{it, rev, allowed})
	if c.order.Len() > c.size {
		delete(c.items, c.order.Remove(c.order.Back()).(*cached).item)
	}
}
