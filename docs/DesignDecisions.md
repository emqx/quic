# Design Decisions

This doc contains design decisions we have made and provides some insights about background and reasons
For each decision.

If you don't agree with the decision or causing issue, please refer to the chapter number in the issue report.

# Decisions

## Resources Managements

1. Connection or Stream should not cross references
    For example, in `s_ctx` it should not have a field `c_ctx`, because stream callback can still get called
    While the `connection` in `c_ctx` is closed due to a close call, is asynchronous.
 
    To avoid getting access to an invalid handle (already closed), there should be no cross references among these resources.

    Access to invalid handles could lead to undefined behavior in MsQuic that includes segfault or abort due to assertions.
 
    However, keep ref counting is still required to avoid the MsQuic handle getting closed too early (it is still in use).
 
1. MsQuic handle
    All MsQuic handlers should be only closed in resource dealloc callback.
 
    For tracking resources usage, quicer do not do refcnt on MsQuic  handlers, instead it relies on the Erlang garbage
    Collection mechanism to track the refcnt on the MsQuic handle.

    To inc refcnt use:
    
    ``` c
    
    enif_make_resource
         
     // OR 
         
    enif_keep_resource

    
    ```
 

    To dec refcnt use:

    `enif_release_resource`

    *CONS*
    - The resources are not closed/freed until the GC kicks in, that means the releasing resources will be delayed.
    
       This behavior also aligns with the delayed GC in BEAM.
       
    - It also requires in the Erlang process not to keep the unused/closed resources in the stack/heap, 
       otherwise it will cause memory leaks.

## Send message to the owner

1. Messages with boxed types are copied to the owner's mailbox. 
