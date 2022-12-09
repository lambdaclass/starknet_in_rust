/// Patricia Merkle Tree implementation.
///
/// For now, keys are always `[u8; 32]`, which represent `KECCAK256` hashes.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PatriciaMerkleTree<V> {
    root_node: Option<Node<V>>,
}

impl<V> PatriciaMerkleTree<V> {
    /// Create an empty tree.
    pub fn new() -> Self {
        todo!()
    }

    /// Check if the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.root_node.is_none()
    }

    /// Insert a key-value into the tree.
    ///
    /// Overwrites and returns the previous value.
    pub fn insert(&mut self, key: &[u8; 32], value: V) -> Option<V> {
        todo!()
    }

    /// Remove a value given its key.
    ///
    /// Returns the removed value.
    pub fn remove(&mut self, key: &[u8; 32]) -> Option<V> {
        todo!()
    }

    /// Retrieves a value given its key.
    pub fn get(&self, key: &[u8; 32]) -> Option<V> {
        todo!()
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum Node<V> {
    Branch(BranchNode<V>),
    Extension(ExtensionNode<V>),
    Leaf(LeafNode<V>),
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

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ExtensionNode<V> {
    // Boolean flag is true if last value in prefix is a nibble (not a byte).
    prefix: (Vec<u8>, bool),
    // The only child type that makes sense here is a branch node, therefore there's no need to wrap
    // it in a `Node<V>`.
    child: BranchNode<V>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct LeafNode<V> {
    key: Vec<u8>,
    value: V,
}

#[cfg(test)]
mod test {
    use super::*;

    macro_rules! pm_tree_key {
        ( $key:literal ) => {{
            assert_eq!($key.len(), 64);
            let key: [u8; 32] = $key
                .as_bytes()
                .chunks_exact(2)
                .map(|x| std::str::from_utf8(x).unwrap().parse::<u8>().unwrap())
                .collect::<Vec<u8>>()
                .try_into()
                .unwrap();

            key
        }};
    }

    macro_rules! pm_tree {
        () => {
            PatriciaMerkleTree {
                root_node: None,
            }
        };
        ( < $t:ty > ) => {
            PatriciaMerkleTree::<$t> {
                root_node: None,
            }
        };
        ( $type:ident { $( $root_node:tt )* } ) => {
            PatriciaMerkleTree {
                root_node: Some(pm_tree!(@parse $type { $( $root_node )* }).into()),
            }
        };

        ( @parse branch { $( $key:literal => $type:ident { $( $node:tt )* } ),* $(,)? } ) => {
            BranchNode {
                choices: {
                    let mut choices: [Option<Box<Node<_>>>; 16] = Default::default();
                    $( choices[$key] = Some(Box::new(pm_tree!(@parse $type { $( $node )* }).into())); )*
                    choices
                },
            }
        };
        ( @parse extension { $prefix:literal, $type:ident { $( $node:tt )* } } ) => {
            ExtensionNode {
                prefix: {
                    let value = $prefix
                        .as_bytes()
                        .chunks(2)
                        .map(|x| match x.len() {
                            2 => std::str::from_utf8(x).unwrap().parse::<u8>().unwrap(),
                            1 => std::str::from_utf8(x).unwrap().parse::<u8>().unwrap() * 0x10,
                            _ => unreachable!(),
                        })
                        .collect::<Vec<u8>>();

                    match $prefix.len() % 2 {
                        0 => (value, false),
                        1 => (value, true),
                        _ => unreachable!(),
                    }
                },
                child: pm_tree!(@parse $type { $( $node )* }).into(),
            }
        };
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

    /// Test that `PatriciaMerkleTree::insert()` works when the tree is empty.
    #[test]
    fn patricia_tree_insert_empty() {
        let key = pm_tree_key!("0000000000000000000000000000000000000000000000000000000000000000");
        let mut pm_tree = pm_tree!();

        assert_eq!(pm_tree.insert(&key, ()), None);
        assert_eq!(
            pm_tree,
            pm_tree! {
                leaf { key.to_vec() => () }
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
            leaf { key_a.to_vec() => () }
        };

        assert_eq!(pm_tree.insert(&key_b, ()), None);
        assert_eq!(
            pm_tree,
            pm_tree! {
                branch {
                    0 => leaf { key_a.to_vec() => () },
                    1 => leaf { key_b.to_vec() => () },
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
            leaf { key_a.to_vec() => () }
        };

        assert_eq!(pm_tree.insert(&key_b, ()), None);
        assert_eq!(
            pm_tree,
            pm_tree! {
                extension { "0", branch {
                    0 => leaf { key_a.to_vec() => () },
                    1 => leaf { key_b.to_vec() => () }
                } }
            }
        );
    }

    /// Test that `PatriciaMerkleTree::insert()` overwrites a leaf value.
    #[test]
    fn patricia_tree_insert_leaf_overwrite() {
        let key = pm_tree_key!("0000000000000000000000000000000000000000000000000000000000000000");
        let mut pm_tree = pm_tree! {
            leaf { key.to_vec() => 0u8 }
        };

        assert_eq!(pm_tree.insert(&key, 1u8), None);
        assert_eq!(
            pm_tree,
            pm_tree! {
                leaf { key.to_vec() => 1u8 }
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
            pm_tree_key!("2000000000000000000000000000000000000000000000000000000000000000");

        let mut pm_tree = pm_tree! {
            branch {
                0 => leaf { key_a.to_vec() => () },
                1 => leaf { key_b.to_vec() => () },
            }
        };

        assert_eq!(pm_tree.insert(&key_c, ()), None);
        assert_eq!(
            pm_tree,
            pm_tree! {
                branch {
                    0 => leaf { key_a.to_vec() => () },
                    1 => leaf { key_b.to_vec() => () },
                    2 => leaf { key_c.to_vec() => () },
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
            pm_tree_key!("0100000000000000000000000000000000000000000000000000000000000000");

        let mut pm_tree = pm_tree! {
            branch {
                0 => leaf { key_a.to_vec() => () },
                1 => leaf { key_b.to_vec() => () },
            }
        };

        assert_eq!(pm_tree.insert(&key_c, ()), None);
        assert_eq!(
            pm_tree,
            pm_tree! {
                branch {
                    0 => branch {
                        0 => leaf { key_a.to_vec() => () },
                        1 => leaf { key_c.to_vec() => () },
                    },
                    1 => leaf { key_b.to_vec() => () },
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
                0 => leaf { key_a.to_vec() => 0u8 },
                1 => leaf { key_b.to_vec() => 1u8 },
            }
        };

        assert_eq!(pm_tree.insert(&key_b, 2u8), None);
        assert_eq!(
            pm_tree,
            pm_tree! {
                branch {
                    0 => leaf { key_a.to_vec() => 0u8 },
                    1 => leaf { key_b.to_vec() => 2u8 },
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
                0 => leaf { key_a.to_vec() => () },
                1 => leaf { key_b.to_vec() => () },
            } }
        };

        assert_eq!(pm_tree.insert(&key_c, ()), None);
        assert_eq!(
            pm_tree,
            pm_tree! {
                branch {
                    0 => extension { "00", branch {
                        0 => leaf { key_a.to_vec() => () },
                        1 => leaf { key_b.to_vec() => () },
                    } },
                    1 => leaf { key_c.to_vec() => () },
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
                0 => leaf { key_a.to_vec() => () },
                1 => leaf { key_b.to_vec() => () },
            } }
        };

        assert_eq!(pm_tree.insert(&key_c, ()), None);
        assert_eq!(
            pm_tree,
            pm_tree! {
                extension { "0", branch {
                    0 => extension { "0", branch {
                        0 => leaf { key_a.to_vec() => () },
                        1 => leaf { key_b.to_vec() => () },
                    } },
                    1 => leaf { key_c.to_vec() => () },
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
                0 => leaf { key_a.to_vec() => () },
                1 => leaf { key_b.to_vec() => () },
            } }
        };

        assert_eq!(pm_tree.insert(&key_c, ()), None);
        assert_eq!(
            pm_tree,
            pm_tree! {
                extension { "00", branch {
                    0 => branch {
                        0 => leaf { key_a.to_vec() => () },
                        0 => leaf { key_b.to_vec() => () },
                    },
                    1 => leaf { key_c.to_vec() => () },
                } }
            }
        );
    }

    // TODO: Design and implement tests for `PatriciaMerkleTree::remove()`.
    // TODO: Design and implement tests for `PatriciaMerkleTree::get()`.
}
