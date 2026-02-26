package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	errVerifyTokenMissing      = errors.New("verification token missing")
	errVerifyTokenInvalid      = errors.New("verification token invalid")
	errVerifyAttemptsExhausted = errors.New("verification attempts exhausted")
)

func decrementTokenAttemptsAtomic(ctx context.Context, rdb *redis.Client, key string, ttlFallback time.Duration, attemptedAt time.Time) (int, error) {
	const maxRetries = 16
	attemptedAt = attemptedAt.UTC()

	for i := 0; i < maxRetries; i++ {
		attemptsLeft := 0

		err := rdb.Watch(ctx, func(tx *redis.Tx) error {
			payload, err := tx.Get(ctx, key).Bytes()
			if err != nil {
				if errors.Is(err, redis.Nil) {
					return errVerifyTokenMissing
				}
				return err
			}

			var token map[string]any
			if err := json.Unmarshal(payload, &token); err != nil {
				return errVerifyTokenInvalid
			}

			attempts, ok := numberToInt(token["attempts_left"])
			if !ok {
				return errVerifyTokenInvalid
			}

			attempts--
			token["attempts_left"] = attempts
			token["last_attempted_at"] = attemptedAt

			if attempts <= 0 {
				_, err := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
					pipe.Del(ctx, key)
					return nil
				})
				if err != nil {
					return err
				}
				return errVerifyAttemptsExhausted
			}

			ttl, ttlErr := tx.TTL(ctx, key).Result()
			if ttlErr != nil || ttl <= 0 {
				ttl = ttlFallback
			}

			updated, err := json.Marshal(token)
			if err != nil {
				return errVerifyTokenInvalid
			}

			_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.Set(ctx, key, updated, ttl)
				return nil
			})
			if err != nil {
				return err
			}

			attemptsLeft = attempts
			return nil
		}, key)

		if err == nil {
			return attemptsLeft, nil
		}
		if errors.Is(err, redis.TxFailedErr) {
			continue
		}
		if errors.Is(err, errVerifyTokenMissing) || errors.Is(err, errVerifyTokenInvalid) || errors.Is(err, errVerifyAttemptsExhausted) {
			return 0, err
		}
		return 0, err
	}

	return 0, fmt.Errorf("failed to decrement attempts atomically for key %s", key)
}

func numberToInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		if n < math.MinInt || n > math.MaxInt {
			return 0, false
		}
		return int(n), true
	case float64:
		if n != math.Trunc(n) || n < math.MinInt || n > math.MaxInt {
			return 0, false
		}
		return int(n), true
	case json.Number:
		i, err := n.Int64()
		if err != nil || i < math.MinInt || i > math.MaxInt {
			return 0, false
		}
		return int(i), true
	default:
		return 0, false
	}
}
