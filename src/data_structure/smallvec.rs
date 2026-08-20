use core::{
    convert::Infallible,
    iter::FromIterator,
    ops::{Deref, DerefMut},
    slice::{Iter, IterMut},
};

use smallvec::{IntoIter, SmallVec};

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct Vec<T, const N: usize>(pub SmallVec<T, N>);

impl<T, const N: usize> Vec<T, N> {
    pub const fn new() -> Self {
        Self(SmallVec::new())
    }
}

impl<T: Clone, const N: usize> Vec<T, N> {
    #[inline(always)]
    pub fn from_slice(slice: &[T]) -> Result<Self, Infallible> {
        let mut v = Self::new();
        v.extend_from_slice(slice)?;
        Ok(v)
    }

    #[inline(always)]
    pub fn extend_from_slice(&mut self, slice: &[T]) -> Result<(), Infallible> {
        self.0.extend_from_slice(slice);
        Ok(())
    }
}

impl<T, const N: usize> Deref for Vec<T, N> {
    type Target = SmallVec<T, N>;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T, const N: usize> DerefMut for Vec<T, N> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T, const N: usize> Vec<T, N> {
    #[inline(always)]
    pub fn push(&mut self, value: T) -> Result<(), Infallible> {
        self.0.push(value);
        Ok(())
    }
}

impl<T, const N: usize> FromIterator<T> for Vec<T, N> {
    #[inline(always)]
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Self(SmallVec::from_iter(iter))
    }
}

impl<T, const N: usize> IntoIterator for Vec<T, N> {
    type Item = T;
    type IntoIter = IntoIter<T, N>;

    #[inline(always)]
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, T, const N: usize> IntoIterator for &'a Vec<T, N> {
    type Item = &'a T;
    type IntoIter = Iter<'a, T>;

    #[inline(always)]
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<'a, T, const N: usize> IntoIterator for &'a mut Vec<T, N> {
    type Item = &'a mut T;
    type IntoIter = IterMut<'a, T>;

    #[inline(always)]
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter_mut()
    }
}
