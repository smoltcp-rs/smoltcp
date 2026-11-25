use alloc::collections::BTreeMap;
use core::{iter::FromIterator, mem::replace};
use heapless::LinearMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmallMap<K: Eq + Ord + Clone, V: Clone, const N: usize> {
    Inline(LinearMap<K, V, N>),
    Heap(BTreeMap<K, V>),
}

impl<K: Eq + Ord + Clone, V: Clone, const N: usize> SmallMap<K, V, N> {
    pub const fn new() -> Self {
        Self::Inline(LinearMap::new())
    }

    #[inline]
    pub fn iter(&self) -> SmallMapIter<'_, K, V, N> {
        match self {
            Self::Inline(map) => SmallMapIter::Inline(map.iter()),
            Self::Heap(map) => SmallMapIter::Heap(map.iter()),
        }
    }

    #[inline]
    pub fn iter_mut(&mut self) -> SmallMapIterMut<'_, K, V, N> {
        match self {
            Self::Inline(map) => SmallMapIterMut::Inline(map.iter_mut()),
            Self::Heap(map) => SmallMapIterMut::Heap(map.iter_mut()),
        }
    }

    #[inline]
    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.iter().map(|(k, _)| k)
    }

    #[inline]
    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.iter().map(|(_, v)| v)
    }

    #[inline]
    pub fn get(&self, key: &K) -> Option<&V> {
        match self {
            Self::Inline(map) => map.get(key),
            Self::Heap(map) => map.get(key),
        }
    }

    #[inline]
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        match self {
            Self::Inline(map) => map.get_mut(key),
            Self::Heap(map) => map.get_mut(key),
        }
    }

    #[inline]
    pub fn remove(&mut self, key: &K) -> Option<V> {
        match self {
            Self::Inline(map) => map.remove(key),
            Self::Heap(map) => map.remove(key),
        }
    }

    #[inline]
    pub fn clear(&mut self) {
        match self {
            Self::Inline(map) => map.clear(),
            Self::Heap(map) => map.clear(),
        }
    }

    #[inline]
    pub fn insert(&mut self, key: K, value: V) -> Result<Option<V>, (K, V)> {
        match self {
            Self::Inline(map) => match map.insert(key, value) {
                Ok(old_val) => Ok(old_val),
                Err((k, v)) => {
                    if let Self::Inline(old_map) = replace(self, Self::Heap(BTreeMap::new())) {
                        let mut heap_map: BTreeMap<K, V> = old_map.into_iter().collect();
                        let res = heap_map.insert(k, v);
                        *self = Self::Heap(heap_map);
                        Ok(res)
                    } else {
                        Err((k, v))
                    }
                }
            },
            Self::Heap(map) => Ok(map.insert(key, value)),
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        match self {
            Self::Inline(map) => map.len(),
            Self::Heap(map) => map.len(),
        }
    }
}

pub enum SmallMapIter<'a, K: 'a, V: 'a, const N: usize> {
    Inline(heapless::linear_map::Iter<'a, K, V>),
    Heap(alloc::collections::btree_map::Iter<'a, K, V>),
}

impl<'a, K, V, const N: usize> Iterator for SmallMapIter<'a, K, V, N> {
    type Item = (&'a K, &'a V);

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Inline(i) => i.next(),
            Self::Heap(i) => i.next(),
        }
    }
}

pub enum SmallMapIterMut<'a, K: 'a, V: 'a, const N: usize> {
    Inline(heapless::linear_map::IterMut<'a, K, V>),
    Heap(alloc::collections::btree_map::IterMut<'a, K, V>),
}

impl<'a, K, V, const N: usize> Iterator for SmallMapIterMut<'a, K, V, N> {
    type Item = (&'a K, &'a mut V);
    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Inline(i) => i.next(),
            Self::Heap(i) => i.next(),
        }
    }
}

pub enum SmallMapIntoIter<K: Eq + Ord + Clone, V: Clone, const N: usize> {
    Inline(heapless::linear_map::IntoIter<K, V, N>),
    Heap(alloc::collections::btree_map::IntoIter<K, V>),
}

impl<K: Eq + Ord + Clone, V: Clone, const N: usize> Iterator for SmallMapIntoIter<K, V, N> {
    type Item = (K, V);
    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Inline(i) => i.next(),
            Self::Heap(i) => i.next(),
        }
    }
}

impl<K: Eq + Ord + Clone, V: Clone, const N: usize> IntoIterator for SmallMap<K, V, N> {
    type Item = (K, V);
    type IntoIter = SmallMapIntoIter<K, V, N>;
    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        match self {
            Self::Inline(map) => SmallMapIntoIter::Inline(map.into_iter()),
            Self::Heap(map) => SmallMapIntoIter::Heap(map.into_iter()),
        }
    }
}

impl<'a, K: Eq + Ord + Clone, V: Clone, const N: usize> IntoIterator for &'a SmallMap<K, V, N> {
    type Item = (&'a K, &'a V);
    type IntoIter = SmallMapIter<'a, K, V, N>;
    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a, K: Eq + Ord + Clone, V: Clone, const N: usize> IntoIterator for &'a mut SmallMap<K, V, N> {
    type Item = (&'a K, &'a mut V);
    type IntoIter = SmallMapIterMut<'a, K, V, N>;
    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

impl<K: Eq + Ord + Clone, V: Clone, const N: usize> FromIterator<(K, V)> for SmallMap<K, V, N> {
    #[inline]
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        let mut iter = iter.into_iter();
        let mut map = LinearMap::new();

        for (k, v) in iter.by_ref() {
            if let Err((k, v)) = map.insert(k, v) {
                return Self::Heap(
                    map.into_iter()
                        .chain(core::iter::once((k, v)))
                        .chain(iter)
                        .collect(),
                );
            }
        }

        Self::Inline(map)
    }
}
