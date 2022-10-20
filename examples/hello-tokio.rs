use std::{future::Future, thread, time::Duration};

use mini_redis::{client, Result};

#[tokio::main]
async fn main() -> Result<()> {
    // let mut client = client::connect("127.0.0.1:6379").await?;
    // client.set("hello", "world".into()).await?;

    // let result = client.get("hello").await?;
    // println!("got {:?}", result);

    // let mut rt = tokio::runtime::Runtime::new().unwrap();
    // let r = rt.block_on(
    //     test_a()
    // );
    // println!("{}", r);

    tokio::spawn(async {
        test_a().await;
    });

    thread::sleep(Duration::from_secs(1));
    // test_a().await;
    Ok(())
}

async fn test_a() -> i32 {
    println!("hello world");
    30
}
