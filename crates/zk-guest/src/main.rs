use tokio::io::BufReader;

#[tokio::main]
async fn main() {
    let stdin = BufReader::new(tokio::io::stdin());
    let stdout = tokio::io::stdout();
    zk_guest::agent::run_agent(stdin, stdout).await;
}
