use std::sync::{Arc, Mutex};

use crate::metrics::Metrics;
use crate::{lox_context, DbConfig};
use chrono::{naive::Days, DateTime, NaiveDateTime, Utc};
use lox_extensions::{BridgeAuth, BridgeDb};
use sled::IVec;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum LoxDBError {
    //failed to get last db entry
    #[error("Failed to read last database entry")]
    ReadFailure(#[from] sled::Error),

    //no last db entries
    #[error("No database entries stored")]
    DatabaseEmpty,
}

pub const DAYS_OF_STORAGE: u64 = 7;

// Database of Lox Distributor State
pub struct DB {
    db: sled::Db,
}

impl DB {
    // Writes the Lox context to the lox database with "context_%Y-%m-%d_%H:%M:%S" as the
    // database key
    pub fn write_context(&mut self, context: lox_context::LoxServerContext) {
        let date = Utc::now().format("context_%Y-%m-%d_%H:%M:%S").to_string();
        /* Uncomment to generate test file for this function after making changes to lox library
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open("db_test_file.json")
            .unwrap();
        serde_json::to_writer(&file, &context).unwrap();
        */
        let json_result = serde_json::to_vec(&context).unwrap();
        println!("Writing context to the db with key: {date}");
        let _new_ivec = self.db.insert(
            IVec::from(date.as_bytes().to_vec()),
            IVec::from(json_result.clone()),
        );
        if self.db.get(IVec::from(date.as_bytes().to_vec())) != Ok(Some(IVec::from(json_result))) {
            println!("Error writing entry with key {date} to database")
        }
    }

    #[cfg(test)]
    pub fn write_test_context(&mut self, context: lox_context::LoxServerContext, past_days: u64) {
        let date = Utc::now()
            .checked_sub_days(Days::new(past_days))
            .unwrap()
            .format("context_%Y-%m-%d_%H:%M:%S")
            .to_string();
        let json_result = serde_json::to_vec(&context).unwrap();
        println!("Writing context to the db with key: {:?}", date);
        let _new_ivec = self.db.insert(
            IVec::from(date.as_bytes().to_vec()),
            IVec::from(json_result.clone()),
        );
        assert_eq!(
            self.db
                .get(IVec::from(date.as_bytes().to_vec()))
                .unwrap()
                .unwrap(),
            IVec::from(json_result)
        );
    }

    // If roll_back_date is empty, opens the most recent entry in the lox database or if none exists, creates a
    // new database. If roll_back_date is not empty, use the specified date to roll back to a previous lox-context
    // either exactly the entry at the roll_back_date or within 24 hours from the roll_back_date.
    pub fn open_new_or_existing_db(
        db_config: DbConfig,
        roll_back_date: Option<String>,
        metrics: Metrics,
    ) -> Result<(DB, lox_context::LoxServerContext), sled::Error> {
        let mut context: lox_context::LoxServerContext;
        let (lox_db, context) = match sled::open(db_config.db_path) {
            Ok(lox_db) => {
                // Check if the lox_db already exists
                if lox_db.was_recovered() && !lox_db.is_empty() {
                    context = match read_lox_context_from_db(lox_db.clone(), roll_back_date) {
                        Ok(ctx) => ctx,
                        Err(e) => panic!("Unable to read lox database {e:?}"),
                    };
                    context.metrics = metrics;
                //Otherwise, create a new Lox context
                } else {
                    let new_db = BridgeDb::new();
                    let rng = &mut rand::thread_rng();
                    let new_ba = BridgeAuth::new(new_db.pubkey, rng);
                    context = lox_context::LoxServerContext {
                        db: Arc::new(Mutex::new(new_db)),
                        ba: Arc::new(Mutex::new(new_ba)),
                        extra_bridges: Arc::new(Mutex::new(Vec::new())),

                        metrics,
                    };
                }
                (DB { db: lox_db }, context)
            }
            Err(e) => {
                panic!("Unable to read or create lox database! {e:?}");
            }
        };
        Ok((lox_db, context))
    }

    // Clear entries from database that are older than DAYS_OF_STORAGE days old
    pub fn clear_old_entries(&self, roll_back_date: Option<String>) -> DateTime<Utc> {
        let mut keep_date = Utc::now()
            .checked_sub_days(Days::new(DAYS_OF_STORAGE))
            .unwrap()
            .format("context_%Y-%m-%d_%H:%M:%S")
            .to_string();
        if let Some(rb_date) = roll_back_date {
            // If roll back date has been specified and the date is in the db, roll back to
            // DAYS_OF_STORAGE
            // days before that date
            if self.db.contains_key(rb_date.clone()).unwrap() {
                let parsed_end =
                    NaiveDateTime::parse_from_str(&rb_date, "context_%Y-%m-%d_%H:%M:%S").unwrap();
                let dt = DateTime::<Utc>::from_naive_utc_and_offset(parsed_end, Utc);
                keep_date = dt
                    .with_timezone(&Utc)
                    .checked_sub_days(Days::new(DAYS_OF_STORAGE))
                    .unwrap()
                    .format("context_%Y-%m-%d_%H:%M:%S")
                    .to_string();
            }
        }
        let mut count = 0;
        println!("Removing entries before {keep_date}");
        while let Ok(Some(_)) = self.db.get_lt(keep_date.as_bytes()) {
            match self.db.pop_min() {
                Ok(entry) => {
                    count += 1;
                    println!(
                        "Removed entry {:?}",
                        std::str::from_utf8(&entry.unwrap().0).unwrap()
                    )
                }
                Err(e) => {
                    panic!("Unable to remove db entry: {e:?}");
                }
            }
        }
        println!("Cleared db of {count} records");
        Utc::now()
    }
}

// Logic for finding the correct context to open from the database
fn read_lox_context_from_db(
    lox_db: sled::Db,
    roll_back_date: Option<String>,
) -> Result<lox_context::LoxServerContext, LoxDBError> {
    let context: lox_context::LoxServerContext;
    // Check if there is a roll back date and try to choose the appropriate context
    // to rollback to, otherwise, take the last saved context

    match roll_back_date {
        // If roll back date has been specified, either the exact date or range should be set
        Some(roll_back_date) => {
            // If the date is specified and it's in the database, use that to populate the context
            if lox_db
                .contains_key(roll_back_date.clone().as_bytes())
                .unwrap()
            {
                // Find date/time in db and use the context from that date.
                let ivec_context = lox_db
                    .get(IVec::from(roll_back_date.as_bytes().to_vec()))
                    .unwrap()
                    .unwrap();
                context = serde_json::from_slice(&ivec_context).unwrap();
                println!("Successfully used exact key {roll_back_date}");
            } else {
                // If the exact date is not found, use the entry immediately prior to the roll_back_date
                let r = lox_db.get_lt(roll_back_date.as_bytes()).unwrap();
                match r {
                    Some(entry) => {
                        let ivec_context = entry;
                        let key: String = String::from_utf8(ivec_context.0.to_vec()).unwrap();
                        println!(
                            "Successfully used date immediately prior to roll_back_date: {key}"
                        );
                        context = serde_json::from_slice(&ivec_context.1).unwrap();
                    }
                    None => panic!(
                        "UNEXPECTED DATE: No entries found prior to the input roll_back_date"
                    ),
                }
            }
        }
        // Use the last entry to populate the Lox context if no rollback date is set (which should be most common)
        None => context = use_last_context(lox_db)?,
    }
    Ok(context)
}

// Use the last context that was entered into the database
fn use_last_context(lox_db: sled::Db) -> Result<lox_context::LoxServerContext, LoxDBError> {
    match lox_db.last()? {
        Some(ivec_context) => {
            let ivec_date: String = String::from_utf8(ivec_context.0.to_vec()).unwrap();
            println!("Using last context with date: {ivec_date}");
            Ok(serde_json::from_slice(&ivec_context.1).unwrap())
        }
        None => Err(LoxDBError::DatabaseEmpty),
    }
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;

    use crate::db_handler::DAYS_OF_STORAGE;

    use super::lox_context::LoxServerContext;
    use super::DbConfig;
    use super::Metrics;
    use super::DB;
    use tempfile::tempdir;

    #[test]
    fn test_write_context() {
        env::set_var("TEST_FILE_PATH", "db_test_file.json");
        // Create a directory inside of `env::temp_dir()`.
        let dir = tempdir().unwrap();
        let conf = DbConfig {
            db_path: dir
                .path()
                .join("lox_db")
                .into_os_string()
                .into_string()
                .unwrap(),
        };
        let (mut lox_db, _context) =
            DB::open_new_or_existing_db(conf, None, Metrics::default()).unwrap();
        assert!(
            lox_db.db.is_empty(),
            "db read from context that shouldn't exist"
        );
        let path = env::var("TEST_FILE_PATH").unwrap();
        let contents = fs::File::open(&path).unwrap();
        //let test_string = std::str::from_utf8(&contents).unwrap();
        let test_context: LoxServerContext = serde_json::from_reader(contents).unwrap();
        lox_db.write_context(test_context);
        assert!(
            lox_db.db.len() == 1,
            "db should have only one context after old entries are cleared"
        );
    }

    #[test]
    fn test_clear_db() {
        env::set_var("TEST_FILE_PATH", "db_test_file.json");
        // Create a directory inside of `env::temp_dir()`.
        let dir = tempdir().unwrap();
        let conf = DbConfig {
            db_path: dir
                .path()
                .join("lox_db")
                .into_os_string()
                .into_string()
                .unwrap(),
        };
        let (mut lox_db, _context) =
            DB::open_new_or_existing_db(conf, None, Metrics::default()).unwrap();
        assert!(
            lox_db.db.is_empty(),
            "db read from context that shouldn't exist"
        );
        let path = env::var("TEST_FILE_PATH").unwrap();
        let contents = fs::File::open(&path).unwrap();
        let test_context: LoxServerContext = serde_json::from_reader(contents).unwrap();
        lox_db.write_test_context(test_context.clone(), DAYS_OF_STORAGE + 2);
        lox_db.write_test_context(test_context.clone(), DAYS_OF_STORAGE + 1);
        lox_db.write_test_context(test_context.clone(), DAYS_OF_STORAGE);
        assert!(
            lox_db.db.len() == 3,
            "db should have written three contexts"
        );
        lox_db.clear_old_entries(None);
        assert!(
            lox_db.db.len() == 1,
            "db should have written only one context"
        );
    }
}
