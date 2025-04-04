# ntprocesses

## About
Rust library that makes it easy to manipulate Windows' processes.
The name comes from the ability to specifically target processes found with the undocumented NtAPI, and use of NtAPI functions. You can use officially supported APIs just as well, too.

## Usage
```toml
[dependencies]
ntprocesses = { git = "https://gitlab.com/ntprocesses/ntprocesses.git" }
```
\- or -
```bash
$ git clone https://gitlab.com/ntprocesses/ntprocesses.git
$ cd ntprocesses
$ cargo test
```

## Examples

#### Getting a process using a snapshot:
```rust
let process = ProcessBuilder::<Attach>::default()
    .permissions(PROCESS_ALL_ACCESS)
    .process_id(process_id)
    .build_from_snapshot()?;
```
#### Getting a process using the NtAPI:
```rust
let process = ProcessBuilder::<Attach>::default()
    .permissions(PROCESS_ALL_ACCESS)
    .process_id(process_id)
    .build_from_nt()?;
```

#### Basic memory operations on a process:
```rust
// this will actually allocate an entire page, read only.
let addr = process.virtual_alloc(None, 1, PAGE_READONLY)?;

// this will set the page to be able to be read and written to.
process.set_protection(addr, 1, PAGE_READWRITE)?;

process.write(addr, 1337 as usize)?;

assert_eq!(process.read::<usize>(addr)?, 1337 as usize);
```

#### Iterate through process threads with undocumented flags:
```rust
let process = Process::<NT>::from_pid(process_id, PROCESS_ALL_ACCESS)?;

for thread process.get_threads() {
    thread.suspend()?;
    println!("{:?}", thread.thread_state);
}
```

#### Thread hijacking made easy with these methods!
```rust
let thread = process.get_threads().next().unwrap();

thread.suspend()
thread.get_context()
thread.set_context()
thread.resume()
// etc ...
```

And, many more examples in the test modules.
