package set

type Set[T comparable] map[T]struct{}

func New[T comparable]() Set[T] {
	return make(Set[T])
}

func NewWithItems[T comparable](items ...T) Set[T] {
	s := make(Set[T])
	for _, item := range items {
		s[item] = struct{}{}
	}
	return s
}

func (s Set[T]) Add(element T) {
	s[element] = struct{}{}
}

func (s Set[T]) Remove(element T) {
	delete(s, element)
}

func (s Set[T]) Contains(element T) bool {
	_, exists := s[element]
	return exists
}

func (s Set[T]) Equals(other Set[T]) bool {
	if len(s) != len(other) {
		return false
	}
	for elem := range s {
		if !other.Contains(elem) {
			return false
		}
	}
	return true
}
