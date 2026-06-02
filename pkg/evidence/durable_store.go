package evidence

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type durableStore struct {
	dirPath string
	nextSeq uint64
	mu      sync.Mutex
}

func newDurableStore(dirPath string) (*durableStore, error) {
	if strings.TrimSpace(dirPath) == "" {
		return nil, fmt.Errorf("durable queue path is required")
	}
	if err := os.MkdirAll(dirPath, 0o700); err != nil {
		return nil, fmt.Errorf("create durable queue dir %s: %w", dirPath, err)
	}

	store := &durableStore{dirPath: dirPath, nextSeq: 1}
	if err := store.initializeNextSequence(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *durableStore) initializeNextSequence() error {
	entries, err := os.ReadDir(s.dirPath)
	if err != nil {
		return fmt.Errorf("read durable queue dir %s: %w", s.dirPath, err)
	}

	var maxSeq uint64
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		seq, err := sequenceFromFilename(entry.Name())
		if err != nil {
			continue
		}
		if seq > maxSeq {
			maxSeq = seq
		}
	}
	if maxSeq > 0 {
		s.nextSeq = maxSeq + 1
	}
	return nil
}

func (s *durableStore) Load() []*BufferedEvent {
	if s == nil {
		return nil
	}

	entries, err := os.ReadDir(s.dirPath)
	if err != nil {
		return nil
	}

	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		files = append(files, entry.Name())
	}
	sort.Strings(files)

	events := make([]*BufferedEvent, 0, len(files))
	for _, name := range files {
		path := filepath.Join(s.dirPath, name)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var event BufferedEvent
		if err := json.Unmarshal(data, &event); err != nil {
			continue
		}
		event.queueKey = filepath.Base(path)
		events = append(events, &event)
	}
	return events
}

func (s *durableStore) Enqueue(event *BufferedEvent) error {
	if s == nil || event == nil {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	fileName := fmt.Sprintf("%020d.json", s.nextSeq)
	s.nextSeq++

	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal durable queue event: %w", err)
	}

	finalPath := filepath.Join(s.dirPath, fileName)
	tempPath := finalPath + ".tmp"
	if err := os.WriteFile(tempPath, payload, 0o600); err != nil {
		return fmt.Errorf("write durable queue event %s: %w", tempPath, err)
	}
	if err := os.Rename(tempPath, finalPath); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("rename durable queue event %s: %w", finalPath, err)
	}

	event.queueKey = fileName
	return nil
}

func (s *durableStore) Ack(events []*BufferedEvent) error {
	if s == nil || len(events) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var errs []string
	for _, event := range events {
		if event == nil || event.queueKey == "" {
			continue
		}
		path := filepath.Join(s.dirPath, filepath.Base(event.queueKey))
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("ack durable queue events: %s", strings.Join(errs, "; "))
	}
	return nil
}

func (s *durableStore) Clear() error {
	if s == nil {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := os.ReadDir(s.dirPath)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		if err := os.Remove(filepath.Join(s.dirPath, entry.Name())); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func sequenceFromFilename(name string) (uint64, error) {
	trimmed := strings.TrimSuffix(filepath.Base(name), ".json")
	return strconv.ParseUint(trimmed, 10, 64)
}
