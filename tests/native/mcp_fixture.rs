//! Hermetic native JSON-RPC peer for command-adapter tests, never a product binary.
use std::io::{self, BufRead, Write};

fn main() {
    let broken=std::env::args().any(|v|v=="--empty");
    for line in io::stdin().lock().lines() {
        let Ok(line)=line else {break};
        let Some(at)=line.find("\"id\":") else {continue};
        let tail=&line[at+5..];
        let id=tail.chars().take_while(|c|c.is_ascii_digit()).collect::<String>();
        if id.is_empty(){continue;}
        let result=if line.contains("\"initialize\"") {
            "{\"protocolVersion\":\"2024-11-05\",\"serverInfo\":{\"name\":\"axiom-mcp\",\"version\":\"0.0.0-test-fixture\"},\"capabilities\":{\"tools\":{}}}"
        } else if line.contains("\"tools/list\"") {
            if broken {"{\"tools\":[]}"}else{"{\"tools\":[{\"name\":\"graph_query\",\"inputSchema\":{\"type\":\"object\"}}]}"}
        } else {"{\"rows\":[{\"node_id\":\"native-fixture-node\"}]}"};
        println!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{result}}}");
        let _=io::stdout().flush();
    }
}
