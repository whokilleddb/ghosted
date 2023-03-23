# Ghosted - A PoC on Process Ghosting

## Introduction
Recently, while researching on ways to make my [exe_who](https://github.com/whokilleddb/exe_who) project more resilient against EDRs and AV engines, I came across the following [blog](https://www.elastic.co/blog/process-ghosting-a-new-executable-image-tampering-attack). The Blog describes a process called Process Ghosting to load executables and that seemed very interesting to me. 

This blog post describes what `Process Ghosting` actually is while  also walking through the steps of creating a Proof-of-concept code for the same in C.




## References
- https://www.elastic.co/blog/process-ghosting-a-new-executable-image-tampering-attack