package state

import (
	"errors"

	"github.com/gerolf-vent/metaleg/internal/utils/set"
)

type StateSource[T any] func() ([]T, error)
type StateAction[T any] func(T) error
type ItemPreparator[T any, K any] func(T) (T, K)
type ItemFilter[T any, K any] func(T, K) bool
type ItemCompare[T any, K any] func(T, K, K) bool

type StateSynchronizer[T any, K any] struct {
	// Retreives the current state items
	Get StateSource[T]

	// Prepares an item from the current state into a comparable form
	Prepare ItemPreparator[T, K]

	// Filters current state items to determine if they should
	// be considered for synchronization
	Filter ItemFilter[T, K]

	// Compares a current state item with a desired state item to determine
	// if they are equal (identity)
	Equal ItemCompare[T, K]

	// Actions to modify the state
	Add    StateAction[K]
	Delete StateAction[T]
}

func (s *StateSynchronizer[T, K]) SyncSingle(item K) error {
	currentItems, err := s.Get()
	if err != nil {
		return err
	}

	preparedItems := make([]K, len(currentItems))
	for i, currentItem := range currentItems {
		currentItems[i], preparedItems[i] = s.Prepare(currentItem)
	}

	found := false
	for i, currentItem := range currentItems {
		preparedItem := preparedItems[i]
		if s.Filter(currentItem, preparedItem) {
			if s.Equal(currentItem, preparedItem, item) {
				found = true
			} else {
				if err := s.Delete(currentItem); err != nil {
					return err
				}
			}
		}
	}

	if !found {
		if err := s.Add(item); err != nil {
			return err
		}
	}

	return nil
}

func (s *StateSynchronizer[T, K]) SyncSet(items []K) error {
	currentItems, err := s.Get()
	if err != nil {
		return err
	}

	preparedItems := make([]K, len(currentItems))
	for i, currentItem := range currentItems {
		currentItems[i], preparedItems[i] = s.Prepare(currentItem)
	}

	deletedItems := set.New[int]()
	existingItems := set.New[int]()

	for i, currentItem := range currentItems {
		preparedItem := preparedItems[i]
		if !s.Filter(currentItem, preparedItem) {
			continue
		}
		shouldDelete := true
		for j, item := range items {
			if s.Equal(currentItem, preparedItem, item) {
				shouldDelete = false
				existingItems.Add(j)
				break
			}
		}
		if shouldDelete {
			if err := s.Delete(currentItem); err != nil {
				return err
			}
			deletedItems.Add(i)
		}
	}

	for i, item := range items {
		if existingItems.Contains(i) {
			continue
		}
		if err := s.Add(item); err != nil {
			return err
		}
	}

	return nil
}

func (s *StateSynchronizer[T, K]) Clear() error {
	currentItems, err := s.Get()
	if err != nil {
		return err
	}

	preparedItems := make([]K, len(currentItems))
	for i, currentItem := range currentItems {
		currentItems[i], preparedItems[i] = s.Prepare(currentItem)
	}

	var errs []error

	for i, currentItem := range currentItems {
		preparedItem := preparedItems[i]
		if s.Filter(currentItem, preparedItem) {
			if err := s.Delete(currentItem); err != nil {
				errs = append(errs, err)
			}
		}
	}

	return errors.Join(errs...)
}
