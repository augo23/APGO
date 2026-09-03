package main

// bencode_encode.go is the write side of bencode. bencode.go decodes tracker
// responses; the DHT (dht.go) also has to SEND bencode, because KRPC (BEP 5)
// is bencode in both directions.
//
// Deliberately minimal and allocation-light: KRPC messages are small, flat
// dicts sent on every routing-table refresh, so this runs far more often than
// the tracker decoder ever did.
//
// Supported Go values: string, []byte, int, int64, []interface{},
// map[string]interface{}. Dict keys are emitted in lexicographic byte order,
// which BEP 5 requires — not for aesthetics, but because some implementations
// hash the raw encoded form and an unsorted dict is silently dropped by them.

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
)

func bencode(v interface{}) ([]byte, error) {
	var out []byte
	err := bencodeInto(&out, v, 0)
	return out, err
}

func bencodeInto(out *[]byte, v interface{}, depth int) error {
	if depth > bdecodeMaxDepth {
		return errors.New("bencode: nesting too deep")
	}
	switch x := v.(type) {
	case string:
		*out = strconv.AppendInt(*out, int64(len(x)), 10)
		*out = append(*out, ':')
		*out = append(*out, x...)
	case []byte:
		*out = strconv.AppendInt(*out, int64(len(x)), 10)
		*out = append(*out, ':')
		*out = append(*out, x...)
	case int:
		*out = append(*out, 'i')
		*out = strconv.AppendInt(*out, int64(x), 10)
		*out = append(*out, 'e')
	case int64:
		*out = append(*out, 'i')
		*out = strconv.AppendInt(*out, x, 10)
		*out = append(*out, 'e')
	case []interface{}:
		*out = append(*out, 'l')
		for _, e := range x {
			if err := bencodeInto(out, e, depth+1); err != nil {
				return err
			}
		}
		*out = append(*out, 'e')
	case []string:
		*out = append(*out, 'l')
		for _, e := range x {
			if err := bencodeInto(out, e, depth+1); err != nil {
				return err
			}
		}
		*out = append(*out, 'e')
	case map[string]interface{}:
		*out = append(*out, 'd')
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if err := bencodeInto(out, k, depth+1); err != nil {
				return err
			}
			if err := bencodeInto(out, x[k], depth+1); err != nil {
				return err
			}
		}
		*out = append(*out, 'e')
	default:
		return fmt.Errorf("bencode: unsupported type %T", v)
	}
	return nil
}

// bdictStr pulls a string field out of a decoded bencode dict. KRPC strings
// are arbitrary BYTES (node IDs, compact endpoints), so the decoder's string
// form is used as-is rather than validated as UTF-8.
func bdictStr(d map[string]interface{}, key string) (string, bool) {
	v, ok := d[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// bdictDict pulls a nested dict out of a decoded bencode dict.
func bdictDict(d map[string]interface{}, key string) (map[string]interface{}, bool) {
	v, ok := d[key]
	if !ok {
		return nil, false
	}
	m, ok := v.(map[string]interface{})
	return m, ok
}

// bdictList pulls a list out of a decoded bencode dict.
func bdictList(d map[string]interface{}, key string) ([]interface{}, bool) {
	v, ok := d[key]
	if !ok {
		return nil, false
	}
	l, ok := v.([]interface{})
	return l, ok
}

// bdictInt pulls an integer out of a decoded bencode dict.
func bdictInt(d map[string]interface{}, key string) (int64, bool) {
	v, ok := d[key]
	if !ok {
		return 0, false
	}
	n, ok := v.(int64)
	return n, ok
}
