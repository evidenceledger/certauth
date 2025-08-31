package cache

import (
	"sync"
	"sync/atomic"
	"time"
)

// Cache stores arbitrary data with expiration time.
type Cache struct {
	items           sync.Map
	counter         atomic.Uint32
	defaultDuration time.Duration
}

// An item represents arbitrary data with expiration time.
type item struct {
	data    any
	expires int64
}

// New creates a new cache that asynchronously cleans
// expired entries after the given time passes.
func New(defaultDuration time.Duration) *Cache {

	if defaultDuration <= 0 {
		defaultDuration = 10 * time.Minute
	}

	cache := &Cache{
		defaultDuration: defaultDuration,
	}

	return cache
}

// Set sets a value for the given key with an expiration duration.
// If the duration is 0 or less, it will be stored forever.
func (cache *Cache) Set(key string, value any, duration time.Duration) {
	var expires int64

	if duration == 0 {
		duration = cache.defaultDuration
	}

	if duration > 0 {
		expires = time.Now().Add(duration).UnixNano()
	}

	cache.items.Store(key, item{
		data:    value,
		expires: expires,
	})

	count := cache.counter.Add(1)

	if count >= 100 {
		cache.DeleteExpired()
		cache.counter.Store(0)
	}
}

// Get gets the value for the given key.
func (cache *Cache) Get(key string) (any, bool) {
	obj, exists := cache.items.Load(key)

	if !exists {
		return nil, false
	}

	item := obj.(item)

	if item.expires > 0 && time.Now().UnixNano() > item.expires {
		cache.items.Delete(key)
		return nil, false
	}

	return item.data, true
}

func (cache *Cache) DeleteExpired() {
	now := time.Now().UnixNano()

	fn := func(key, value any) bool {
		item := value.(item)

		if item.expires > 0 && now > item.expires {
			cache.items.Delete(key)
		}

		return true
	}

	cache.items.Range(fn)

}

// Delete deletes the key and its value from the cache.
func (cache *Cache) Delete(key string) {
	cache.items.Delete(key)
}
