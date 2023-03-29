# Ghosted - A PoC on Process Ghosting

## Introduction
`Process Ghosting` is a technique of running EXE payloads that has already been deleted. On Windows. it is possible to create a file, put it in a delete pending stage, write your payload to it, map it to an image section for it, close the file handle to delete the file and then finally create a process from the mapped image section. This, essentially, is the `Process Ghosting` process.  In this way, the created process does not have an associated executable file on disk which makes detections difficult for certain EDRs/AV engines.

![Process Ghosting](./img/PoC_Ghosting.png)

## Processes Spawned Up, Callbacks Thrown Up [🎵](https://www.youtube.com/shorts/XO5gYTHo6HI)


An interesting question to ask is how do Security vendors scan processes? One of the methods, [as described my Microsoft in this post](https://www.microsoft.com/en-us/security/blog/2022/06/30/using-process-creation-properties-to-catch-evasion-techniques/), goes as follows:

> Process creation callbacks in the kernel, such as those provided by the [_PsSetCreateProcessNotifyRoutineEx_](https://docs.microsoft.com/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex) API, is the functionality in the operating system that allows antimalware engines to inspect a process while it’s being created. It can intercept the creation of a process and perform a scan on the relevant executable, all before the process runs.

However, there is a catch. Looking at the documentation for [`PsSetCreateProcessNotifyRoutineEx`](https://docs.microsoft.com/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex), notice the following part:

> When a process is created, the process-notify routine runs in the context of the thread that created the new process. When a process is deleted, the process-notify routine runs in the context of the last thread to exit from the process.

This means that callbacks are registered only when the first thread is spawned, which gives malware a window between time of creation and the time at which security vendors are notified about it. It is in this interval that malware can carry out image tampering leading to attacks like `Process Doppelgänging`, `Process Herpaderping` and `Process Ghosting`.

## Show and Tell

First, let us write a demo application which we will use to demonstrate certain artifacts throughout:

```c
// demo.c
#include <windows.h>
#include <stdio.h>

int main() {
	printf("Hello From PID: %d\n", GetCurrentProcessId());
	getchar();
	return 0;
}
```

Compiling and running this program outputs the process's PID. Running the process and inspecting it's properties in _Process Hacker2_ shows the following:

![](./img/demo_in_ph2.png)

Notice how the `demo.exe` executable is listed as the `Image File name` for the process? However, one can delete the executable and the process would still be live. Quoting Gabriel Landau here:

> It’s important to note that processes are not executables, and executables are not processes.

This [blog](https://fourcore.io/blogs/how-a-windows-process-is-created-part-2) does a good job of explaining the process creation flow carried out by [CreateProcess()](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa) to launch a process on Windows. Long story short, Windows uses function calls like `NtCreateUserProcess()` to launch a process, but the indiviual API components can also be called to launch a process. 

The steps to launch a process from an executable can be summarized as such:
- Open an Executable file and get a handle to it
- Create an `Image Section` for the file and map the appropriate memory
- Create a Process out of the mapped section
- Assign appropriate environment variables and process arguments
- Create a Thread to execute the process



## Talk is Cheap, Show me the code!

Time to walk through the code flow for the project! The code is written in C because: 
- It helps to understand everything going on at a very fundamental level
- Because I can.

Right away, the `main()` 


## References
- https://www.elastic.co/blog/process-ghosting-a-new-executable-image-tampering-attack
- https://fourcore.io/blogs/how-a-windows-process-is-created-part-1
- https://dosxuz.gitlab.io/post/processghosting/