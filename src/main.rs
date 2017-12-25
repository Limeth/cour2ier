extern crate r2pipe;
extern crate serde_json;

use r2pipe::R2Pipe;
use serde_json::Value;

fn register_cmd(r2p: &mut R2Pipe, label: &str) {
    r2p.cmd(&format!("${0}=#!pipe $COUR2IER_PATH {0}", label))
        .expect(&format!("Could not register command `{}`.", label));
}

fn register_cmds(r2p: &mut R2Pipe, labels: &[&str]) {
    for label in labels {
        register_cmd(r2p, label);
    }
}

fn get_pointer_bytes(r2p: &mut R2Pipe) -> u64 {
    r2p.cmdj("iAj")
        .expect("Could not query arch info.")["bins"][0]["bits"]
        .as_u64().unwrap() / 8
}

fn get_stack_pointers(r2p: &mut R2Pipe) -> (u64, u64) {
    let mut sp: Option<u64> = None;
    let mut bp: Option<u64> = None;

    match r2p.cmdj("drj").expect("Could not query registers.") {
        Value::Object(map) => {
            for (key, value) in map {
                if key.ends_with("sp") {
                    sp = value.as_u64();
                } else if key.ends_with("bp") {
                    bp = value.as_u64();
                }
            }
        },
        _ => (),
    }

    (
        sp.expect("Could not resolve the stack pointer value."),
        bp.expect("Could not resolve the base pointer value.")
    )
}

fn read_value_at(r2p: &mut R2Pipe, pointer_size: u64, position: u64) -> u64 {
    let mut result: u64 = 0;

    match r2p.cmdj(&format!("pxj {} @ {}", pointer_size, position)).unwrap() {
        Value::Array(vec) => {
            for item in vec.iter().rev() {
                result = (result << 8) + item.as_u64().unwrap();
            }
        },
        _ => panic!(),
    }

    result
}

fn main() {
    let args: Vec<_> = std::env::args().collect();

    if R2Pipe::in_session().is_none() {
        println!("Run this binary from within r2 using `#!pipe {}`", args[0]);
        return;
    }

    let mut r2p = R2Pipe::open()
        .expect("Could not connect to the radare2 session.");

    'dance:
    while args.len() > 1 {
        match args[1].as_ref() {
            "init" => {
                r2p.cmd(&format!("env COUR2IER_PATH={}", args[0])).unwrap();

                register_cmds(&mut r2p, &[
                    "stackframe",
                    "dashboard",
                    "start",
                ]);

                println!("Cour2ier initialized.");
            },
            "stackframe" => {
                let pointer_size = get_pointer_bytes(&mut r2p);
                let (mut sp, mut bp) = get_stack_pointers(&mut r2p);

                let sf_index = if args.len() > 2 {
                    match args[2].parse::<usize>() {
                        Err(_) => {
                            println!("Invalid stackframe index: {}", args[2]);
                            return;
                        },
                        Ok(sf_index) => {
                            sf_index
                        },
                    }
                } else {
                    0
                };

                for i in (1..).take(sf_index) {
                    sp = bp + pointer_size;
                    bp = read_value_at(&mut r2p, pointer_size, bp);

                    if bp == 0 {
                        println!("Stack frame index out of bounds. Number of available stack frames: {}", i);
                        return;
                    }
                }

                if sp > bp {
                    println!("W0t. Your pointers are switched.");
                    return;
                }

                let total_bytes = bp - sp + pointer_size;

                println!("Stack frame #{}:", sf_index);

                println!("{}", r2p.cmd(
                    &format!("px {0} @ {1}", total_bytes, sp)
                ).unwrap());
            },
            "dashboard" => {
                println!("{}", r2p.cmd(
r#"?e \nCurrent function:;
pdf;
?e \nVariables:;
afvd;
?e \nRegisters:;
dr="#
                ).unwrap());
            },
            "start" => {
                println!("{}", r2p.cmd("aaa; db main; dc; ds 3").unwrap());
            },
            _ => break 'dance,
        }

        return;
    }

    println!(
r#"Usage:
{0} init  -- Initializes cour2ier within r2
{0} start  -- Starts debugging in the main function
{0} dashboard  -- Displays relevant debugging info
{0} stackframe [index]  -- Prints out the stackframe"#,
        args[0]
    );
}
