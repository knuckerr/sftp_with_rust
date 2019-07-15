use std::rc::Rc;

extern crate serde;
extern crate serde_json;
extern crate ssh2;

#[macro_use]
extern crate serde_derive;

extern crate clap;
use clap::{App, Arg};

use ssh2::Session;
use std::net::TcpStream;
mod mirror;
mod server;
use mirror::{clean_old_files, last_modified, mirror, notify};
use server::*;
use std::error::Error;

use std::collections::HashMap;

struct Arguments<'a> {
    server_name: &'a str,
    project_path: &'a str,
    version: &'a str,
    revision: &'a str,
    extra_commands: HashMap<&'a str, bool>,
}

fn create_ssh(arguments: Arguments) -> Result<(), Box<Error>> {
    let servers = Servers::new()?;
    let server: Vec<Server> = servers
        .servers
        .into_iter()
        .filter(|x| x.name == arguments.server_name)
        .collect();
    
    if server.len() > 0 {
        let server = server[0].to_owned();
        let tcp = TcpStream::connect(format!("{}:{}", server.ip, server.port))?;
        let mut sess = Session::new().unwrap();
        sess.handshake(&tcp)?;
        sess.userauth_password(&server.username, &server.password)
            .unwrap();
        sess.authenticated();
        let sess_clone = Rc::new(sess);
        if arguments.revision != "None" {
            server.revision(Rc::clone(&sess_clone), arguments.revision)?;
            return Ok(());
        }
        if *arguments.extra_commands.get("clean").unwrap() {
            clean_old_files(
                Rc::clone(&sess_clone),
                server.to_owned(),
                arguments.project_path,
            )?;
        }

        if *arguments.extra_commands.get("versions").unwrap() {
            let list_version = server.list_versions(Rc::clone(&sess_clone));
            if list_version.is_err() {
                eprintln!("{}", list_version.unwrap_err());
            }
            return Ok(());
        }
        let files = last_modified(
            arguments.project_path,
            arguments.version,
            server.to_owned().exlude,
        )?;
        mirror(
            Rc::clone(&sess_clone),
            server.to_owned(),
            arguments.project_path,
            files,
        )?;
        if *arguments.extra_commands.get("live").unwrap() {
            notify(
                Rc::clone(&sess_clone),
                arguments.project_path,
                server.to_owned(),
            )?;
        }
        if *arguments.extra_commands.get("backup").unwrap() {
            server.create_backup(Rc::clone(&sess_clone), arguments.version)?;
        }
    } else {
        println!(
            "Server with name {} not found on json file",
            arguments.server_name
        );
    }
    Ok(())
}

fn main() {
    let matches = App::new("My Super Program")
        .version("0.1")
        .author("Knucker. <johnkalafatasb@gmail.com>")
        .about("Project mirror")
        .arg(
            Arg::with_name("server")
                .long("server")
                .help("Sets the remote server")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("mirror")
                .long("mirror")
                .help("Sets the local folder")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("version")
                .long("version")
                .help("Sets the version of the update")
                .takes_value(true),
        )
        .arg( Arg::with_name("revision")
                .long("revision")
                .help("roll back on specific version")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("backup")
                .long("backup")
                .help("Create Backup of the remote server files")
                .required(false)
                .takes_value(false),
        )
        .arg(
            Arg::with_name("clean")
                .long("clean")
                .help("Clean old files that remain on server folder")
                .required(false)
                .takes_value(false),
        )
        .arg(
            Arg::with_name("versions")
                .long("versions")
                .help("List of versions that exist on server")
                .required(false)
                .takes_value(false),
        )
        .arg(
            Arg::with_name("live")
                .long("live")
                .help(
                    "Create live listener on the local folder and any changes upload to the server",
                )
                .required(false)
                .takes_value(false),
        )
        .get_matches();
    let server_name = matches.value_of("server").unwrap();
    let main_path = matches.value_of("mirror").unwrap();
    let version = matches.value_of("version").unwrap_or("0.1");

    let revision = matches.value_of("revision").unwrap_or("None");
    let mut extra_commands = HashMap::new();
    let mut backup = false;
    let mut clean = false;
    let mut live = false;
    let mut versions = false;

    match matches.occurrences_of("backup") {
        1 => backup = true,
        _ => {}
    }
    match matches.occurrences_of("clean") {
        1 => clean = true,
        _ => {}
    }

    match matches.occurrences_of("live") {
        1 => live = true,
        _ => {}
    }

    match matches.occurrences_of("versions") {
        1 => versions = true,
        _ => {}
    }


    extra_commands.insert("backup", backup);
    extra_commands.insert("clean", clean);
    extra_commands.insert("live", live);
    extra_commands.insert("versions", versions);

    let arguments = Arguments {
        server_name: server_name,
        project_path: main_path,
        version: version,
        revision: revision,
        extra_commands: extra_commands,
    };
    let ssh_check = create_ssh(arguments);
    if ssh_check.is_err() {
        eprintln!("{}", ssh_check.unwrap_err());
    }
}
