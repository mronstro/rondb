--------------------------------- MODULE MC ---------------------------------
(***************************************************************************)
(* The values of the model runs (README.md). Two node groups of two        *)
(* replicas; row a on n1 (primary) and n2, row b on n3 (primary) and n4.   *)
(* t1 writes a and b, with its TC on n3, the primary of b; t2 writes a,    *)
(* with its TC on n2, the backup of a, which gets the linear COMMIT and    *)
(* COMPLETE first. td, in the dirty-write runs, writes b with its TC on    *)
(* n1. t0 has a GCI <= R_gcp and the transid of t1: its COMMIT and         *)
(* COMPLETE of a are before the tail in the logs of n1 and n2, as the      *)
(* API node-id hold-back of X4.11 puts them (DI-2).                        *)
(***************************************************************************)
EXTENDS DurableCommits

MCNodes == {"n1", "n2", "n3", "n4"}
MCNG == [n \in MCNodes |-> IF n \in {"n1", "n2"} THEN 1 ELSE 2]
MCRows == {"a", "b"}
MCChain == [r \in MCRows |-> IF r = "a" THEN <<"n1", "n2">>
                                         ELSE <<"n3", "n4">>]

MCAllTxns == {"t1", "t2", "td"}
MCTxns == {"t1", "t2"}
MCTxnsDirty == {"t1", "t2", "td"}
MCTxnRows == [t \in MCAllTxns |-> CASE t = "t1" -> {"a", "b"}
                                    [] t = "t2" -> {"a"}
                                    [] OTHER -> {"b"}]
MCTC == [t \in MCAllTxns |-> CASE t = "t1" -> "n3"
                               [] t = "t2" -> "n2"
                               [] OTHER -> "n1"]
MCDirtyNone == {}
MCDirtyTd == {"td"}

MCOldTxn == "t0"
MCTransId == [t \in MCAllTxns \cup {"t0"} |-> CASE t = "t2" -> "x2"
                                                [] t = "td" -> "xd"
                                                [] OTHER -> "x1"]
OldRec(type) ==
    [type |-> type, tid |-> "x1", txn |-> "t0", row |-> "a",
     opc |-> 1, self |-> FALSE, tail |-> FALSE]
MCOldLog == [n \in MCNodes |->
                IF n \in {"n1", "n2"} THEN <<OldRec("COMMIT"), OldRec("COMPLETE")>>
                                      ELSE <<>>]

MCPaths == {"linear", "parallel"}

=============================================================================
