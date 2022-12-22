//! # Patricia Merkle Tree
//!
//! This module implements a Patricia Merkle tree. Hashing is done externally to
//! keep different modules separated and ease testing.
//!
//! By default, values are stored in memory. If storage is required, the value
//! can be made to be a pointer to the item in the storage.

use std::mem::swap;

/// Patricia Merkle Tree implementation.
///
/// For now, keys are always `[u8; 32]`, which represent `KECCAK256` hashes.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PatriciaMerkleTree<V> {
    root_node: Option<Node<V>>,
}

impl<V> PatriciaMerkleTree<V> {
    /// Create an empty tree.
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self { root_node: None }
    }

    /// Check if the tree is empty.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.root_node.is_none()
    }

    /// Retrieves a value given its key.
    #[allow(dead_code)]
    pub fn get(&self, key: &[u8; 32]) -> Option<&V> {
        self.root_node
            .as_ref()
            .and_then(|root_node| root_node.get(key, 0))
    }

    /// Insert a key-value into the tree.
    ///
    /// Overwrites and returns the previous value.
    #[allow(dead_code)]
    pub fn insert(&mut self, key: &[u8; 32], value: V) -> Option<V> {
        if let Some(root_node) = self.root_node.take() {
            let (root_node, old_value) = root_node.insert(key, value, 0);
            self.root_node = Some(root_node);

            old_value
        } else {
            self.root_node = Some(
                LeafNode {
                    key: key.to_owned(),
                    value,
                }
                .into(),
            );

            None
        }
    }

    /// Remove a value given its key.
    ///
    /// Returns the removed value.
    #[allow(dead_code)]
    pub fn remove(&mut self, key: &[u8; 32]) -> Option<V> {
        if let Some(root_node) = self.root_node.take() {
            let (root_node, old_value) = root_node.remove(key, 0);
            self.root_node = root_node;

            old_value
        } else {
            None
        }
    }

    #[allow(dead_code)]
    pub fn iter(&self) -> TreeIterator<V> {
        TreeIterator::new(self)
    }

    #[allow(dead_code)]
    pub fn drain_filter<F>(&mut self, mut filter: F) -> Vec<([u8; 32], V)>
    where
        F: FnMut(&[u8; 32], &mut V) -> bool,
    {
        if let Some(root_node) = self.root_node.take() {
            let mut drained_items = Vec::new();
            self.root_node = root_node.drain_filter(&mut filter, &mut drained_items, 0);
            drained_items
        } else {
            Vec::new()
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum Node<V> {
    Branch(BranchNode<V>),
    Extension(ExtensionNode<V>),
    Leaf(LeafNode<V>),
}

impl<V> Node<V> {
    pub fn get(&self, key: &[u8; 32], current_key_offset: usize) -> Option<&V> {
        match self {
            Node::Branch(branch_node) => return branch_node.get(key, current_key_offset),
            Node::Extension(extension_node) => {
                if KeySegmentIterator::new(key)
                    .skip(current_key_offset)
                    .zip(extension_node.prefix.iter().copied())
                    .all(|(a, b)| a == b)
                {
                    return extension_node
                        .child
                        .get(key, current_key_offset + extension_node.prefix.len());
                }
            }
            Node::Leaf(leaf_node) => {
                if leaf_node.key == *key {
                    return Some(&leaf_node.value);
                }
            }
        }

        None
    }

    fn insert(self, key: &[u8; 32], value: V, current_key_offset: usize) -> (Self, Option<V>) {
        match self {
            Node::Branch(branch_node) => {
                let (new_node, old_value) = branch_node.insert(key, value, current_key_offset);
                (new_node.into(), old_value)
            }
            Node::Extension(extension_node) => {
                let (new_node, old_value) = extension_node.insert(key, value, current_key_offset);
                (new_node, old_value)
            }
            Node::Leaf(leaf_node) => {
                let (new_node, old_value) = leaf_node.insert(key, value, current_key_offset);
                (new_node, old_value)
            }
        }
    }

    fn remove(self, key: &[u8; 32], current_key_offset: usize) -> (Option<Self>, Option<V>) {
        match self {
            Node::Branch(branch_node) => branch_node.remove(key, current_key_offset),
            Node::Extension(extension_node) => extension_node.remove(key, current_key_offset),
            Node::Leaf(leaf_node) => leaf_node.remove(key),
        }
    }

    fn drain_filter<F>(
        self,
        filter: &mut F,
        drained_items: &mut Vec<([u8; 32], V)>,
        current_key_offset: usize,
    ) -> Option<Self>
    where
        F: FnMut(&[u8; 32], &mut V) -> bool,
    {
        match self {
            Node::Branch(branch_node) => {
                branch_node.drain_filter(filter, drained_items, current_key_offset)
            }
            Node::Extension(extension_node) => {
                extension_node.drain_filter(filter, drained_items, current_key_offset)
            }
            Node::Leaf(leaf_node) => leaf_node.drain_filter(filter, drained_items),
        }
    }
}

impl<V> From<BranchNode<V>> for Node<V> {
    fn from(value: BranchNode<V>) -> Self {
        Self::Branch(value)
    }
}

impl<V> From<ExtensionNode<V>> for Node<V> {
    fn from(value: ExtensionNode<V>) -> Self {
        Self::Extension(value)
    }
}

impl<V> From<LeafNode<V>> for Node<V> {
    fn from(value: LeafNode<V>) -> Self {
        Self::Leaf(value)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct BranchNode<V> {
    choices: [Option<Box<Node<V>>>; 16],
}

impl<V> BranchNode<V> {
    fn get(&self, key: &[u8; 32], current_key_offset: usize) -> Option<&V> {
        self.choices[KeySegmentIterator::nth(key, current_key_offset) as usize]
            .as_ref()
            .and_then(|node| node.get(key, current_key_offset + 1))
    }

    fn insert(mut self, key: &[u8; 32], value: V, current_key_offset: usize) -> (Self, Option<V>) {
        let mut old_value = None;
        self.choices[KeySegmentIterator::nth(key, current_key_offset) as usize] = Some(match self
            .choices[KeySegmentIterator::nth(key, current_key_offset) as usize]
            .take()
        {
            Some(mut x) => {
                let new_node;
                (new_node, old_value) = x.insert(key, value, current_key_offset + 1);
                *x = new_node;
                x
            }
            None => Box::new(
                LeafNode {
                    key: key.to_owned(),
                    value,
                }
                .into(),
            ),
        });

        (self, old_value)
    }

    fn remove(mut self, key: &[u8; 32], current_key_offset: usize) -> (Option<Node<V>>, Option<V>) {
        let index = KeySegmentIterator::nth(key, current_key_offset) as usize;
        match self.choices[index].take() {
            Some(mut child_node) => {
                let (new_child, old_value) = child_node.remove(key, current_key_offset + 1);
                if let Some(new_child) = new_child {
                    *child_node = new_child;
                    self.choices[index] = Some(child_node);
                }

                let mut single_child = None;
                for child in self.choices.iter_mut() {
                    if child.is_none() {
                        continue;
                    }

                    match single_child {
                        Some(_) => return (Some(self.into()), old_value),
                        None => single_child = Some(child),
                    }
                }

                (
                    match single_child {
                        Some(x) => match x.take() {
                            Some(x) => Some(*x),
                            None => unreachable!(),
                        },
                        None => None,
                    },
                    old_value,
                )
            }
            None => (Some(self.into()), None),
        }
    }

    fn drain_filter<F>(
        mut self,
        filter: &mut F,
        drained_items: &mut Vec<([u8; 32], V)>,
        current_key_offset: usize,
    ) -> Option<Node<V>>
    where
        F: FnMut(&[u8; 32], &mut V) -> bool,
    {
        enum SingleChild {
            NoChildren,
            Single(usize),
            Multiple,
        }

        let mut single_child = SingleChild::NoChildren;
        for (index, choice) in self.choices.iter_mut().enumerate() {
            *choice = match choice.take() {
                Some(old_node) => old_node
                    .drain_filter(filter, drained_items, current_key_offset + 1)
                    .map(|new_node| {
                        single_child = match single_child {
                            SingleChild::NoChildren => SingleChild::Single(index),
                            _ => SingleChild::Multiple,
                        };

                        Box::new(new_node)
                    }),
                None => None,
            };
        }

        match single_child {
            SingleChild::NoChildren => None,
            SingleChild::Single(index) => self.choices[index].take().map(|x| *x),
            SingleChild::Multiple => Some(self.into()),
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ExtensionNode<V> {
    // Each value is a nibble.
    prefix: Vec<u8>,
    // The only child type that makes sense here is a branch node, therefore there's no need to wrap
    // it in a `Node<V>`.
    child: BranchNode<V>,
}

impl<V> ExtensionNode<V> {
    fn insert(
        mut self,
        key: &[u8; 32],
        value: V,
        current_key_offset: usize,
    ) -> (Node<V>, Option<V>) {
        match KeySegmentIterator::new(key)
            .skip(current_key_offset)
            .enumerate()
            .zip(self.prefix.iter().copied())
            .find_map(|((idx, a), b)| (a != b).then_some((idx, a, b)))
        {
            Some((prefix_len, value_b, value_a)) => (
                if prefix_len == 0 {
                    self.prefix.remove(0);

                    BranchNode {
                        choices: {
                            let mut choices: [Option<Box<Node<V>>>; 16] = Default::default();

                            choices[value_a as usize] = Some(Box::new(self.into()));
                            choices[value_b as usize] = Some(Box::new(
                                LeafNode {
                                    key: key.to_owned(),
                                    value,
                                }
                                .into(),
                            ));

                            choices
                        },
                    }
                    .into()
                } else {
                    let branch_node = BranchNode {
                        choices: {
                            let mut choices: [Option<Box<Node<V>>>; 16] = Default::default();

                            choices[value_a as usize] =
                                Some(Box::new(if prefix_len != self.prefix.len() - 1 {
                                    let (_, new_prefix) = self.prefix.split_at(prefix_len + 1);
                                    ExtensionNode {
                                        prefix: new_prefix.to_vec(),
                                        child: self.child,
                                    }
                                    .into()
                                } else {
                                    self.child.into()
                                }));
                            choices[value_b as usize] = Some(Box::new(
                                LeafNode {
                                    key: key.to_owned(),
                                    value,
                                }
                                .into(),
                            ));

                            choices
                        },
                    };

                    self.prefix.truncate(prefix_len);
                    ExtensionNode {
                        prefix: self.prefix,
                        child: branch_node,
                    }
                    .into()
                },
                None,
            ),
            None => {
                let old_value;
                (self.child, old_value) =
                    self.child
                        .insert(key, value, current_key_offset + self.prefix.len());
                (self.into(), old_value)
            }
        }
    }

    fn remove(mut self, key: &[u8; 32], current_key_offset: usize) -> (Option<Node<V>>, Option<V>) {
        let (new_child, old_value) = self
            .child
            .remove(key, current_key_offset + self.prefix.len());

        (
            match new_child {
                Some(Node::Branch(branch_node)) => {
                    self.child = branch_node;
                    Some(self.into())
                }
                Some(Node::Extension(extension_node)) => {
                    self.prefix.extend(extension_node.prefix.into_iter());
                    self.child = extension_node.child;
                    Some(self.into())
                }
                Some(Node::Leaf(leaf_node)) => Some(leaf_node.into()),
                None => None,
            },
            old_value,
        )
    }

    fn drain_filter<F>(
        mut self,
        filter: &mut F,
        drained_items: &mut Vec<([u8; 32], V)>,
        current_key_offset: usize,
    ) -> Option<Node<V>>
    where
        F: FnMut(&[u8; 32], &mut V) -> bool,
    {
        let new_child = self.child.drain_filter(
            filter,
            drained_items,
            current_key_offset + self.prefix.len(),
        );

        match new_child {
            Some(Node::Branch(branch_node)) => {
                self.child = branch_node;
                Some(self.into())
            }
            Some(Node::Extension(extension_node)) => {
                self.prefix.extend(extension_node.prefix.into_iter());
                self.child = extension_node.child;
                Some(self.into())
            }
            Some(Node::Leaf(leaf_node)) => Some(leaf_node.into()),
            None => None,
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct LeafNode<V> {
    key: [u8; 32],
    value: V,
}

impl<V> LeafNode<V> {
    fn insert(
        mut self,
        key: &[u8; 32],
        value: V,
        current_key_offset: usize,
    ) -> (Node<V>, Option<V>) {
        match KeySegmentIterator::new(key)
            .zip(KeySegmentIterator::new(&self.key))
            .skip(current_key_offset)
            .enumerate()
            .find_map(|(idx, (a, b))| (a != b).then_some((idx, a, b)))
        {
            Some((prefix_len, value_b, value_a)) => {
                let leaf_a = self;
                let leaf_b = LeafNode {
                    key: key.to_owned(),
                    value,
                };

                let branch_node = BranchNode {
                    choices: {
                        let mut choices: [Option<Box<Node<V>>>; 16] = Default::default();

                        choices[value_a as usize] = Some(Box::new(leaf_a.into()));
                        choices[value_b as usize] = Some(Box::new(leaf_b.into()));

                        choices
                    },
                };

                let node: Node<V> = if prefix_len == 0 {
                    branch_node.into()
                } else {
                    ExtensionNode {
                        prefix: KeySegmentIterator::new(key).take(prefix_len).collect(),
                        child: branch_node,
                    }
                    .into()
                };

                (node, None)
            }
            _ => {
                let mut value = value;
                swap(&mut value, &mut self.value);
                (self.into(), Some(value))
            }
        }
    }

    fn remove(self, key: &[u8; 32]) -> (Option<Node<V>>, Option<V>) {
        if *key == self.key {
            (None, Some(self.value))
        } else {
            (Some(self.into()), None)
        }
    }

    fn drain_filter<F>(
        mut self,
        filter: &mut F,
        drained_items: &mut Vec<([u8; 32], V)>,
    ) -> Option<Node<V>>
    where
        F: FnMut(&[u8; 32], &mut V) -> bool,
    {
        if filter(&self.key, &mut self.value) {
            drained_items.push((self.key, self.value));
            None
        } else {
            Some(self.into())
        }
    }
}

/// `KECCAK256` key nibble iterator.
struct KeySegmentIterator<'a> {
    data: &'a [u8; 32],
    pos: usize,
    half: bool,
}

impl<'a> KeySegmentIterator<'a> {
    /// Create a new nibble iterator.
    pub fn new(data: &'a [u8; 32]) -> Self {
        Self {
            data,
            pos: 0,
            half: false,
        }
    }

    /// Shortcut to the `nth()` method of a new iterator.
    ///
    /// Panics when n is out of the range [0, 64).
    pub fn nth(data: &'a [u8; 32], n: usize) -> u8 {
        KeySegmentIterator::new(data)
            .nth(n)
            .expect("Key index out of range, value should be in [0, 64).")
    }
}

impl<'a> Iterator for KeySegmentIterator<'a> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= 32 {
            return None;
        }

        let mut value = self.data[self.pos];

        if self.half {
            self.pos += 1;
            value &= 0xF;
        } else {
            value >>= 4;
        }

        self.half = !self.half;
        Some(value)
    }
}

/// Iterator state (for each node, like a stack).
///
/// The `Node<V>` enum can't be used because it doesn't handle special cases such as the
/// `ExtensionNode`'s child well.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct NodeState<'a, V> {
    node: &'a BranchNode<V>,
    state: usize,
}

pub struct TreeIterator<'a, V> {
    tree: Option<&'a PatriciaMerkleTree<V>>,
    state: Vec<NodeState<'a, V>>,
}

impl<'a, V> TreeIterator<'a, V> {
    fn new(tree: &'a PatriciaMerkleTree<V>) -> Self {
        Self {
            tree: Some(tree),
            state: vec![],
        }
    }
}

impl<'a, V> Iterator for TreeIterator<'a, V> {
    type Item = (&'a [u8; 32], &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(tree) = self.tree.take() {
                self.state.push(match &tree.root_node {
                    Some(root_node) => {
                        let current_node = root_node;
                        NodeState {
                            node: match current_node {
                                Node::Branch(branch_node) => branch_node,
                                Node::Extension(extension_node) => &extension_node.child,
                                Node::Leaf(leaf_node) => {
                                    break Some((&leaf_node.key, &leaf_node.value))
                                }
                            },
                            state: 0,
                        }
                    }
                    None => break None,
                });
            }

            match self.state.pop() {
                Some(last_state) if last_state.state < last_state.node.choices.len() => {
                    self.state.push(NodeState {
                        node: last_state.node,
                        state: last_state.state + 1,
                    });

                    if let Some(choice) = &last_state.node.choices[last_state.state] {
                        self.state.push(NodeState {
                            node: match choice.as_ref() {
                                Node::Branch(branch_node) => branch_node,
                                Node::Extension(extension_node) => &extension_node.child,
                                Node::Leaf(leaf_node) => {
                                    break Some((&leaf_node.key, &leaf_node.value))
                                }
                            },
                            state: 0,
                        });
                    }
                }
                None => break None,
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// Create a new Patricia Merkle tree key.
    macro_rules! pm_tree_key {
        ( $key:literal ) => {{
            assert_eq!($key.len(), 64, "Tree keys must be 64 nibbles in length.");
            let key: [u8; 32] = $key
                .as_bytes()
                .chunks_exact(2)
                .map(|x| {
                    u8::from_str_radix(std::str::from_utf8(x).unwrap(), 16)
                        .expect("Key contains non-hexadecimal characters.")
                })
                .collect::<Vec<u8>>()
                .try_into()
                .unwrap();

            key
        }};
    }

    /// Create a new Patricia Merkle Tree.
    macro_rules! pm_tree {
        // Create an empty tree (with deduced value type).
        () => {
            PatriciaMerkleTree {
                root_node: None,
            }
        };
        // Create an empty tree (with explicit value type).
        ( < $t:ty > ) => {
            PatriciaMerkleTree::<$t> {
                root_node: None,
            }
        };
        // Create a new tree.
        ( $type:ident { $( $root_node:tt )* } ) => {
            PatriciaMerkleTree {
                root_node: Some(pm_tree!(@parse $type { $( $root_node )* }).into()),
            }
        };

        // Internal.
        ( @parse branch { $( $key:literal => $type:ident { $( $node:tt )* } ),* $(,)? } ) => {
            BranchNode {
                choices: {
                    let mut choices: [Option<Box<Node<_>>>; 16] = Default::default();
                    $( choices[$key] = Some(Box::new(pm_tree!(@parse $type { $( $node )* }).into())); )*
                    choices
                },
            }
        };
        // Internal.
        ( @parse extension { $prefix:literal, $type:ident { $( $node:tt )* } } ) => {
            ExtensionNode {
                prefix: {
                    let value = $prefix
                        .as_bytes()
                        .into_iter()
                        .map(|x| {
                            (*x as char)
                                .to_digit(16)
                                .expect("Prefix contains non-hexadecimal characters.") as u8
                        })
                        .collect::<Vec<u8>>();

                    value
                },
                child: pm_tree!(@parse $type { $( $node )* }).into(),
            }
        };
        // Internal.
        ( @parse leaf { $key:expr => $value:expr } ) => {
            LeafNode {
                key: $key,
                value: $value,
            }
        };
    }

    /// Test that `PatriciaMerkleTree` can be initialized.
    #[test]
    fn patricia_tree_new() {
        assert_eq!(PatriciaMerkleTree::<()>::new(), pm_tree!());
    }

    /// Test that `PatriciaMerkleTree::is_empty()` works as intended.
    #[test]
    fn patricia_tree_is_empty() {
        assert!(pm_tree!(<()>).is_empty());
    }

    /// Test that `PatriciaMerkleTree::get()` works when the tree is empty.
    #[test]
    fn patricia_tree_get_empty() {
        let key = pm_tree_key!("0000000000000000000000000000000000000000000000000000000000000000");
        let pm_tree = pm_tree!(<()>);

        assert_eq!(pm_tree.get(&key).copied(), None);
    }

    /// Test that `PatriciaMerkleTree::get()` works across with leaf nodes.
    #[test]
    fn patricia_tree_get_leaf() {
        let key = pm_tree_key!("0000000000000000000000000000000000000000000000000000000000000000");
        let pm_tree = pm_tree! {
            leaf { key => 42 }
        };

        assert_eq!(pm_tree.get(&key).copied(), Some(42));
    }

    /// Test that `PatriciaMerkleTree::get()` works across extension nodes.
    #[test]
    fn patricia_tree_get_extension() {
        let key_a =
            pm_tree_key!("0000000000000000000000000000000000000000000000000000000000000000");
        let key_b =
            pm_tree_key!("0001000000000000000000000000000000000000000000000000000000000000");
        let key_c =
            pm_tree_key!("0002000000000000000000000000000000000000000000000000000000000000");
        let key_d =
            pm_tree_key!("0200000000000000000000000000000000000000000000000000000000000000");

        let pm_tree = pm_tree! {
            extension { "000", branch {
                0 => leaf { key_a => 42 },
                1 => leaf { key_b => 43 },
            } }
        };

        assert_eq!(pm_tree.get(&key_a).copied(), Some(42));
        assert_eq!(pm_tree.get(&key_b).copied(), Some(43));
        assert_eq!(pm_tree.get(&key_c).copied(), None);
        assert_eq!(pm_tree.get(&key_d).copied(), None);
    }

    /// Test that `PatriciaMerkleTree::get()` works across branch nodes.
    #[test]
    fn patricia_tree_get_branch() {
        let key_a =
            pm_tree_key!("0000000000000000000000000000000000000000000000000000000000000000");
        let key_b =
            pm_tree_key!("1000000000000000000000000000000000000000000000000000000000000000");
        let key_c =
            pm_tree_key!("2000000000000000000000000000000000000000000000000000000000000000");

        let pm_tree = pm_tree! {
            branch {
                0 => leaf { key_a => 42 },
                1 => leaf { key_b => 43 },
            }
        };

        assert_eq!(pm_tree.get(&key_a).copied(), Some(42));
        assert_eq!(pm_tree.get(&key_b).copied(), Some(43));
        assert_eq!(pm_tree.get(&key_c).copied(), None);
    }

    /// Test that `PatriciaMerkleTree::insert()` works when the tree is empty.
    #[test]
    fn patricia_tree_insert_empty() {
        let key = pm_tree_key!("0000000000000000000000000000000000000000000000000000000000000000");
        let mut pm_tree = pm_tree!();

        assert_eq!(pm_tree.insert(&key, ()), None);
        assert_eq!(
            pm_tree,
            pm_tree! {
                leaf { key => () }
            },
        );
    }

    /// Test that `PatriciaMerkleTree::insert()` works when combining on a leaf node, when the first
    /// character is differing.
    #[test]
    fn patricia_tree_insert_leaf_beginning() {
        let key_a =
            pm_tree_key!("0000000000000000000000000000000000000000000000000000000000000000");
        let key_b =
            pm_tree_key!("1000000000000000000000000000000000000000000000000000000000000000");

        let mut pm_tree = pm_tree! {
            leaf { key_a => () }
        };

        assert_eq!(pm_tree.insert(&key_b, ()), None);
        assert_eq!(
            pm_tree,
            pm_tree! {
                branch {
                    0 => leaf { key_a => () },
                    1 => leaf { key_b => () },
                }
            }
        );
    }

    /// Test that `PatriciaMerkleTree::insert()` works when combining on a leaf node, when the first
    /// differing character is in the middle.
    #[test]
    fn patricia_tree_insert_leaf_middle() {
        let key_a =
            pm_tree_key!("0000000000000000000000000000000000000000000000000000000000000000");
        let key_b =
            pm_tree_key!("0100000000000000000000000000000000000000000000000000000000000000");

        let mut pm_tree = pm_tree! {
            leaf { key_a => () }
        };

        assert_eq!(pm_tree.insert(&key_b, ()), None);
        assert_eq!(
            pm_tree,
            pm_tree! {
                extension { "0", branch {
                    0 => leaf { key_a => () },
                    1 => leaf { key_b => () }
                } }
            }
        );
    }

    /// Test that `PatriciaMerkleTree::insert()` overwrites a leaf value.
    #[test]
    fn patricia_tree_insert_leaf_overwrite() {
        let key = pm_tree_key!("0000000000000000000000000000000000000000000000000000000000000000");
        let mut pm_tree = pm_tree! {
            leaf { key => 0u8 }
        };

        assert_eq!(pm_tree.insert(&key, 1u8), Some(0));
        assert_eq!(
            pm_tree,
            pm_tree! {
                leaf { key => 1u8 }
            }
        );
    }

    /// Test that `PatriciaMerkleTree::insert()` works by inserting a new branch.
    #[test]
    fn patricia_tree_insert_branch() {
        let key_a =
            pm_tree_key!("0000000000000000000000000000000000000000000000000000000000000000");
        let key_b =
            pm_tree_key!("1000000000000000000000000000000000000000000000000000000000000000");
        let key_c =
            pm_tree_key!("0100000000000000000000000000000000000000000000000000000000000000");

        let mut pm_tree = pm_tree! {
            branch {
                0 => leaf { key_a => () },
                1 => leaf { key_b => () },
            }
        };

        assert_eq!(pm_tree.insert(&key_c, ()), None);
        assert_eq!(
            pm_tree,
            pm_tree! {
                branch {
                    0 => branch {
                        0 => leaf { key_a => () },
                        1 => leaf { key_c => () },
                    },
                    1 => leaf { key_b => () },
                }
            }
        );
    }

    /// Test that `PatriciaMerkleTree::insert()` works by inserting into an existing branch.
    #[test]
    fn patricia_tree_extend_branch() {
        let key_a =
            pm_tree_key!("0000000000000000000000000000000000000000000000000000000000000000");
        let key_b =
            pm_tree_key!("1000000000000000000000000000000000000000000000000000000000000000");
        let key_c =
            pm_tree_key!("2000000000000000000000000000000000000000000000000000000000000000");

        let mut pm_tree = pm_tree! {
            branch {
                0 => leaf { key_a => () },
                1 => leaf { key_b => () },
            }
        };

        assert_eq!(pm_tree.insert(&key_c, ()), None);
        assert_eq!(
            pm_tree,
            pm_tree! {
                branch {
                    0 => leaf { key_a => () },
                    1 => leaf { key_b => () },
                    2 => leaf { key_c => () },
                }
            }
        );
    }

    /// Test that `PatriciaMerkleTree::insert()` works by overwriting an existing branch's child.
    #[test]
    fn patricia_tree_insert_branch_overwrite() {
        let key_a =
            pm_tree_key!("0000000000000000000000000000000000000000000000000000000000000000");
        let key_b =
            pm_tree_key!("1000000000000000000000000000000000000000000000000000000000000000");

        let mut pm_tree = pm_tree! {
            branch {
                0 => leaf { key_a => 0u8 },
                1 => leaf { key_b => 1u8 },
            }
        };

        assert_eq!(pm_tree.insert(&key_b, 2u8), Some(1));
        assert_eq!(
            pm_tree,
            pm_tree! {
                branch {
                    0 => leaf { key_a => 0u8 },
                    1 => leaf { key_b => 2u8 },
                }
            }
        );
    }

    /// Test that `PatriciaMerkleTree::insert()` works by splitting an extension in the beginning.
    #[test]
    fn patricia_tree_insert_extension_beginning() {
        let key_a =
            pm_tree_key!("0000000000000000000000000000000000000000000000000000000000000000");
        let key_b =
            pm_tree_key!("0001000000000000000000000000000000000000000000000000000000000000");
        let key_c =
            pm_tree_key!("1000000000000000000000000000000000000000000000000000000000000000");

        let mut pm_tree = pm_tree! {
            extension { "000", branch {
                0 => leaf { key_a => () },
                1 => leaf { key_b => () },
            } }
        };

        assert_eq!(pm_tree.insert(&key_c, ()), None);
        assert_eq!(
            pm_tree,
            pm_tree! {
                branch {
                    0 => extension { "00", branch {
                        0 => leaf { key_a => () },
                        1 => leaf { key_b => () },
                    } },
                    1 => leaf { key_c => () },
                }
            }
        );
    }

    /// Test that `PatriciaMerkleTree::insert()` works by splitting an extension in the middle.
    #[test]
    fn patricia_tree_insert_extension_middle() {
        let key_a =
            pm_tree_key!("0000000000000000000000000000000000000000000000000000000000000000");
        let key_b =
            pm_tree_key!("0001000000000000000000000000000000000000000000000000000000000000");
        let key_c =
            pm_tree_key!("0100000000000000000000000000000000000000000000000000000000000000");

        let mut pm_tree = pm_tree! {
            extension { "000", branch {
                0 => leaf { key_a => () },
                1 => leaf { key_b => () },
            } }
        };

        assert_eq!(pm_tree.insert(&key_c, ()), None);
        assert_eq!(
            pm_tree,
            pm_tree! {
                extension { "0", branch {
                    0 => extension { "0", branch {
                        0 => leaf { key_a => () },
                        1 => leaf { key_b => () },
                    } },
                    1 => leaf { key_c => () },
                } }
            }
        );
    }

    /// Test that `PatriciaMerkleTree::insert()` works by splitting an extension in the end.
    #[test]
    fn patricia_tree_insert_extension_end() {
        let key_a =
            pm_tree_key!("0000000000000000000000000000000000000000000000000000000000000000");
        let key_b =
            pm_tree_key!("0001000000000000000000000000000000000000000000000000000000000000");
        let key_c =
            pm_tree_key!("0010000000000000000000000000000000000000000000000000000000000000");

        let mut pm_tree = pm_tree! {
            extension { "000", branch {
                0 => leaf { key_a => () },
                1 => leaf { key_b => () },
            } }
        };

        assert_eq!(pm_tree.insert(&key_c, ()), None);
        assert_eq!(
            pm_tree,
            pm_tree! {
                extension { "00", branch {
                    0 => branch {
                        0 => leaf { key_a => () },
                        1 => leaf { key_b => () },
                    },
                    1 => leaf { key_c => () },
                } }
            }
        );
    }

    /// Test that `PatriciaMerkleTree::remove()` removes the root node.
    #[test]
    fn patricia_tree_remove_root() {
        let key_a =
            pm_tree_key!("0000000000000000000000000000000000000000000000000000000000000000");
        let key_b =
            pm_tree_key!("1000000000000000000000000000000000000000000000000000000000000000");

        let mut pm_tree = pm_tree! {
            leaf { key_a => () }
        };

        assert_eq!(pm_tree.remove(&key_b), None);
        assert_eq!(pm_tree.remove(&key_a), Some(()));
        assert_eq!(pm_tree, pm_tree!());
    }

    /// Test that `PatriciaMerkleTree::remove()` removes branch nodes' children.
    #[test]
    fn patricia_tree_remove_branch() {
        let key_a =
            pm_tree_key!("0000000000000000000000000000000000000000000000000000000000000000");
        let key_b =
            pm_tree_key!("1000000000000000000000000000000000000000000000000000000000000000");

        let mut pm_tree = pm_tree! {
            branch {
                0 => leaf { key_a => () },
                1 => leaf { key_b => () },
            }
        };

        assert_eq!(pm_tree.remove(&key_a), Some(()));
        assert_eq!(
            pm_tree,
            pm_tree! {
                leaf { key_b => () }
            }
        );
    }

    /// Test that `PatriciaMerkleTree::remove()` removes branch nodes' children.
    #[test]
    fn patricia_tree_remove_branch2() {
        let key_a =
            pm_tree_key!("0000000000000000000000000000000000000000000000000000000000000000");
        let key_b =
            pm_tree_key!("1000000000000000000000000000000000000000000000000000000000000000");
        let key_c =
            pm_tree_key!("2000000000000000000000000000000000000000000000000000000000000000");

        let mut pm_tree = pm_tree! {
            branch {
                0 => leaf { key_a => () },
                1 => leaf { key_b => () },
                2 => leaf { key_c => () },
            }
        };

        assert_eq!(pm_tree.remove(&key_a), Some(()));
        assert_eq!(
            pm_tree,
            pm_tree! {
                branch {
                    1 => leaf { key_b => () },
                    2 => leaf { key_c => () },
                }
            }
        );
    }

    /// Test that `PatriciaMerkleTree::remove()` removes branch nodes.
    #[test]
    fn patricia_tree_remove_last_branch() {
        let key_a =
            pm_tree_key!("0000000000000000000000000000000000000000000000000000000000000000");
        let key_b =
            pm_tree_key!("1000000000000000000000000000000000000000000000000000000000000000");

        let mut pm_tree = pm_tree! {
            branch {
                0 => leaf { key_a => () },
                1 => leaf { key_b => () },
            }
        };

        assert_eq!(pm_tree.remove(&key_a), Some(()));
        assert_eq!(pm_tree.remove(&key_b), Some(()));
        assert_eq!(pm_tree, pm_tree!());
    }

    /// Test that `PatriciaMerkleTree::remove()` removes extension nodes.
    #[test]
    fn patricia_tree_remove_extension() {
        let key_a =
            pm_tree_key!("0000000000000000000000000000000000000000000000000000000000000000");
        let key_b =
            pm_tree_key!("0100000000000000000000000000000000000000000000000000000000000000");

        let mut pm_tree = pm_tree! {
            extension { "0", branch {
                0 => leaf { key_a => () },
                1 => leaf { key_b => () },
            } }
        };

        assert_eq!(pm_tree.remove(&key_a), Some(()));
        assert_eq!(pm_tree.remove(&key_b), Some(()));
        assert_eq!(pm_tree, pm_tree!());
    }

    /// Test that `PatriciaMerkleTree::remove()` combines extensions correctly.
    #[test]
    fn patricia_tree_remove_extension_combine() {
        let key_a =
            pm_tree_key!("0000000000000000000000000000000000000000000000000000000000000000");
        let key_b =
            pm_tree_key!("0100000000000000000000000000000000000000000000000000000000000000");
        let key_c =
            pm_tree_key!("0001000000000000000000000000000000000000000000000000000000000000");

        let mut pm_tree = pm_tree! {
            extension { "0", branch {
                0 => extension { "00", branch {
                    0 => leaf { key_a => () },
                    1 => leaf { key_c => () },
                } },
                1 => leaf { key_b => () },
            } }
        };

        assert_eq!(pm_tree.remove(&key_b), Some(()));
        assert_eq!(
            pm_tree,
            pm_tree! {
                extension { "000", branch {
                    0 => leaf { key_a => () },
                    1 => leaf { key_c => () },
                } }
            },
        );
    }

    /// Test that `KeySegmentIterator` works as intended.
    #[test]
    fn key_segment_iterator() {
        let key = pm_tree_key!("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        let segment_iter = KeySegmentIterator::new(&key);

        assert!(segment_iter.enumerate().all(|(i, x)| i % 16 == x as usize));
    }

    /// Test that an iterator over an empty tree works as intended.
    #[test]
    fn patricia_tree_iter_empty() {
        let pm_tree = pm_tree!(<()>);
        assert_eq!(pm_tree.iter().collect::<Vec<_>>(), vec![]);
    }

    /// Test that an iterator over a leaf node has multiple children and no data can be extracted.
    #[test]
    fn patricia_tree_iter_branch() {
        let key_a =
            pm_tree_key!("0000000000000000000000000000000000000000000000000000000000000000");
        let key_b =
            pm_tree_key!("1000000000000000000000000000000000000000000000000000000000000000");
        let key_c =
            pm_tree_key!("8000000000000000000000000000000000000000000000000000000000000000");
        let key_d =
            pm_tree_key!("f000000000000000000000000000000000000000000000000000000000000000");

        let pm_tree = pm_tree! {
            branch {
                0x00 => leaf { key_a => 0x00u8 },
                0x01 => leaf { key_b => 0x01u8 },
                0x08 => leaf { key_c => 0x08u8 },
                0x0F => leaf { key_d => 0x0Fu8 },
            }
        };

        assert_eq!(
            pm_tree.iter().collect::<Vec<_>>(),
            vec![
                (&key_a, &0x00),
                (&key_b, &0x01),
                (&key_c, &0x08),
                (&key_d, &0x0F),
            ],
        );
    }

    /// Test that an iterator over a leaf node has one child and no data can be extracted.
    #[test]
    fn patricia_tree_iter_extension() {
        let key_a =
            pm_tree_key!("0000000000000000000000000000000000000000000000000000000000000000");
        let key_b =
            pm_tree_key!("0001000000000000000000000000000000000000000000000000000000000000");

        let pm_tree = pm_tree! {
            extension { "000", branch {
                0 => leaf { key_a => 0u8 },
                1 => leaf { key_b => 1u8 },
            } }
        };

        assert_eq!(
            pm_tree.iter().collect::<Vec<_>>(),
            vec![(&key_a, &0), (&key_b, &1)],
        );
    }

    /// Test that an iterator over a leaf node has no children and allows data to be extracted.
    #[test]
    fn patricia_tree_iter_leaf() {
        let key = pm_tree_key!("0000000000000000000000000000000000000000000000000000000000000000");
        let pm_tree = pm_tree! {
            leaf { key => () }
        };

        assert_eq!(pm_tree.iter().collect::<Vec<_>>(), vec![(&key, &())]);
    }

    /// Test that `PatriciaMerkleTree::drain_filter()` removes the root node.
    #[test]
    fn patricia_tree_drain_filter_root() {
        let key = pm_tree_key!("0000000000000000000000000000000000000000000000000000000000000000");

        let mut pm_tree = pm_tree! {
            leaf { key => () }
        };

        assert_eq!(pm_tree.drain_filter(|_, _| true), vec![(key, ())]);
        assert_eq!(pm_tree, pm_tree!());
    }

    /// Test that `PatriciaMerkleTree::drain_filter()` removes branch nodes' children.
    #[test]
    fn patricia_tree_drain_filter_branch() {
        let key_a =
            pm_tree_key!("0000000000000000000000000000000000000000000000000000000000000000");
        let key_b =
            pm_tree_key!("1000000000000000000000000000000000000000000000000000000000000000");

        let mut pm_tree = pm_tree! {
            branch {
                0 => leaf { key_a => () },
                1 => leaf { key_b => () },
            }
        };

        assert_eq!(pm_tree.drain_filter(|k, _| k == &key_a), vec![(key_a, ())]);
        assert_eq!(
            pm_tree,
            pm_tree! {
                leaf { key_b => () }
            }
        );
    }

    /// Test that `PatriciaMerkleTree::drain_filter()` removes branch nodes' children.
    #[test]
    fn patricia_tree_drain_filter_branch2() {
        let key_a =
            pm_tree_key!("0000000000000000000000000000000000000000000000000000000000000000");
        let key_b =
            pm_tree_key!("1000000000000000000000000000000000000000000000000000000000000000");
        let key_c =
            pm_tree_key!("2000000000000000000000000000000000000000000000000000000000000000");

        let mut pm_tree = pm_tree! {
            branch {
                0 => leaf { key_a => () },
                1 => leaf { key_b => () },
                2 => leaf { key_c => () },
            }
        };

        assert_eq!(pm_tree.drain_filter(|k, _| k == &key_a), vec![(key_a, ())]);
        assert_eq!(
            pm_tree,
            pm_tree! {
                branch {
                    1 => leaf { key_b => () },
                    2 => leaf { key_c => () },
                }
            }
        );
    }

    /// Test that `PatriciaMerkleTree::drain_filter()` removes branch nodes.
    #[test]
    fn patricia_tree_drain_filter_last_branch() {
        let key_a =
            pm_tree_key!("0000000000000000000000000000000000000000000000000000000000000000");
        let key_b =
            pm_tree_key!("1000000000000000000000000000000000000000000000000000000000000000");

        let mut pm_tree = pm_tree! {
            branch {
                0 => leaf { key_a => () },
                1 => leaf { key_b => () },
            }
        };

        assert_eq!(
            pm_tree.drain_filter(|_, _| true),
            vec![(key_a, ()), (key_b, ())],
        );
        assert_eq!(pm_tree, pm_tree!());
    }

    /// Test that `PatriciaMerkleTree::drain_filter()` removes extension nodes.
    #[test]
    fn patricia_tree_drain_filter_extension() {
        let key_a =
            pm_tree_key!("0000000000000000000000000000000000000000000000000000000000000000");
        let key_b =
            pm_tree_key!("0100000000000000000000000000000000000000000000000000000000000000");

        let mut pm_tree = pm_tree! {
            extension { "0", branch {
                0 => leaf { key_a => () },
                1 => leaf { key_b => () },
            } }
        };

        assert_eq!(
            pm_tree.drain_filter(|_, _| true),
            vec![(key_a, ()), (key_b, ())],
        );
        assert_eq!(pm_tree, pm_tree!());
    }

    /// Test that `PatriciaMerkleTree::drain_filter()` combines extensions correctly.
    #[test]
    fn patricia_tree_drain_filter_extension_combine() {
        let key_a =
            pm_tree_key!("0000000000000000000000000000000000000000000000000000000000000000");
        let key_b =
            pm_tree_key!("0100000000000000000000000000000000000000000000000000000000000000");
        let key_c =
            pm_tree_key!("0001000000000000000000000000000000000000000000000000000000000000");

        let mut pm_tree = pm_tree! {
            extension { "0", branch {
                0 => extension { "00", branch {
                    0 => leaf { key_a => () },
                    1 => leaf { key_c => () },
                } },
                1 => leaf { key_b => () },
            } }
        };

        assert_eq!(pm_tree.drain_filter(|k, _| k == &key_b), vec![(key_b, ())],);
        assert_eq!(
            pm_tree,
            pm_tree! {
                extension { "000", branch {
                    0 => leaf { key_a => () },
                    1 => leaf { key_c => () },
                } }
            },
        );
    }
}
