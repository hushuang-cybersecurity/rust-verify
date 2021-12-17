#![feature(rustc_private)]
extern crate pad;
extern crate proc_macro;
extern crate regex;
extern crate rustc_ast;
extern crate rustc_ast_pretty;
extern crate rustc_error_codes;
extern crate rustc_errors;
extern crate rustc_hash;
extern crate rustc_hir;
extern crate rustc_interface;
extern crate rustc_parse;
extern crate rustc_session;
extern crate rustc_span;
extern crate walkdir;
extern crate rustc_driver;

use regex::Regex;
use std::thread::spawn;
use rustc_ast::visit;
use rustc_parse::parse_crate_from_file;
use rustc_session::parse::ParseSess;
use rustc_span::edition::Edition;
use walkdir::{DirEntry, WalkDir};
use rustc_span::with_session_globals;

use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    time::Instant,
    path::Path,
    fs::File,
};

mod util;
mod visitor; // visitor 实现部分
use util::{is_rs, count_lines};
use visitor::{BOStruct};

fn main() {

    let benchmark = "/Users/hushuang/Desktop/rust-security/benchmark";
    let walker = WalkDir::new(benchmark.to_string()).into_iter();

    //statistics of lines
    let mut total_lines = 0;
    let mut file_count = 0;
    let rs_regex = Regex::new(r"^(.*/)*(.)+(\.)(.+)(\.rs)$").unwrap();

    // create error log file

    //time consuming
    let start = Instant::now();

    //walk dir
    for entry in walker {
        let entry = entry.unwrap();
        /*let file_name = entry.file_name().to_str();
        match file_name {
            Some(f) =>{
                println!("{:#?}",f);
            }
            _ =>{}
            
        }*/
        
        let error_log_file_path = create_error_file();
        println!("{}", entry.path().display());
        if is_rs(&entry, &rs_regex) {
            file_count += 1;
            total_lines += count_lines(&entry);
            parse_one_file(&entry, &error_log_file_path);
        }
    }

    let time_cost = start.elapsed().as_millis();

    println!("\n");
    println!("Total RS Files :{}", file_count);
    println!("Total  Lines :{}\n", total_lines);
    println!("Time cost: {:?} ms", time_cost); // ms
}

fn parse_one_file(entry: &DirEntry, error_log_file_path: &String) {
    let sg = rustc_span::SessionGlobals :: new (Edition::Edition2018);
    rustc_span::with_session_globals(Edition::Edition2018, || {
        let parse_session = ParseSess::with_silent_emitter();
        let mut visitor = BOStruct {
            file_name: entry.path().to_str().unwrap().to_string(),
            is_unsafe: Default::default(),
            is_index: Default::default(),
            is_def: Default::default(),
            temp: Default::default(),
            def_list: Default::default(),
            use_list: Default::default(),
            times: 0,
            source_map: parse_session.source_map().clone(),
            line: Default::default(),
            localleft: Default::default(),
            error_log_file_path: error_log_file_path,
        };

        match catch_unwind(AssertUnwindSafe(|| {
            parse_crate_from_file(entry.path(), &parse_session)
        })) {
            Ok(Ok(ast_krate)) => {
                visit::walk_crate(&mut visitor, &ast_krate);
                // println!("定义列表长度：{}", visitor.def_list.len());
                // read_vec(&visitor.def_list);
                // println!("使用列表长度：{}", visitor.use_list.len());
                // read_vec(&visitor.use_list);
            }
            Ok(Err(mut err)) => err.cancel(),
            _ => {}
        };
    });
}

fn read_vec(var_list: &Vec<String>) {
    for var in var_list {
        println!("{}", var);
    }
}
pub fn create_error_file() -> String {
    let file_name = "test.fs";
    let path_str = format!("/Users/hushuang/Desktop/rust-security/data/{}.txt", file_name);
    let error_log_file_path = Path::new(&path_str);
    match File::create(&error_log_file_path){
        Err(..) => panic!("couldn't create {}", error_log_file_path.display()),
        Ok(file) =>file,
    };
    path_str
}
