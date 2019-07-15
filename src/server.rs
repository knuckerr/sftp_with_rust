extern crate serde;
extern crate serde_json;

extern crate serde_derive;

use std::error::Error;
use std::fs::File;
use std::io::Read;

use ssh2::Session;

use std::path::Path;

use std::rc::Rc;

use crate::mirror::fix_version_path;

#[derive(Serialize, Clone, Debug, Deserialize)]
pub struct Servers {
    pub servers: Vec<Server>,
}

#[derive(Serialize, Clone, Debug, Default, Deserialize)]
pub struct Server {
    pub name: String,
    pub ip: String,
    pub port: String,
    pub side_mirror: String,
    pub backup_folder: String,
    pub projectname: String,
    pub username: String,
    pub password: String,
    pub commands: Vec<String>,
    pub exlude: Vec<String>,
}

impl Servers {
    pub fn new() -> Result<Servers, Box<Error>> {
        let mut server_file = File::open("server.json")?;
        let mut data = String::new();
        server_file.read_to_string(&mut data)?;
        let servers: Servers = serde_json::from_str(&data)?;
        Ok(servers)
    }
}

impl Server {
    pub fn create_backup(&self, sess: Rc<Session>, version: &str) -> Result<(), Box<Error>> {
        let sftp = sess.sftp()?;
        let path = format!("/{}/versions", self.projectname);

        let check_logs = fix_version_path(Rc::clone(&sess), &self.projectname, version);
        if check_logs.is_err() {
            eprintln!("{}", check_logs.unwrap_err());
        }

        let check_file = sftp.open(Path::new(&path));
        if check_file.is_err() {
            sftp.mkdir(Path::new(&path), 0o775)?;
        }
        let mut channel = sess.channel_session()?;
        let backup_command = format!(
            "tar -cvf {}/versions/{}.tar --overwrite {}",
            self.projectname, version, &self.side_mirror
        );
        println!("Creating Backup...Calling tar command on server");
        channel.exec(&backup_command)?;
        let mut s = String::new();
        channel.read_to_string(&mut s)?;
        println!("{}", s);
        Ok(())
    }

    pub fn list_versions(&self, sess: Rc<Session>) -> Result<(), Box<Error>> {
        let path = format!("/{}/versions/", self.projectname);

        let mut channel = sess.channel_session()?;
        let list_command = format!("ls {}*.tar", &path);
        channel.exec(&list_command)?;
        let mut s = String::new();
        channel.read_to_string(&mut s)?;
        if s.len() == 0 {
            println!("No versions found");
        }
        println!("{}", s);
        Ok(())
    }
    pub fn revision(&self, sess: Rc<Session>, revision_version: &str) -> Result<(), Box<Error>> {
        let sftp = sess.sftp()?;
        let path = format!("{}/versions/{}.tar", self.projectname, revision_version);

        let check_file = sftp.open(Path::new(&path));
        if check_file.is_err() {
            println!("THE VERSION FILE {} NOT FOUND", path);
            return Ok(());
        }
        let mut channel = sess.channel_session()?;
        let command = format!(
            "tar xvkf {}/versions/{}.tar --overwrite  --strip-components=1 -C {} ",
            self.projectname, revision_version, &self.side_mirror
        );
        println!(
            "Untar the version {}.tar FILE to the server",
            revision_version
        );
        channel.exec(&command)?;
        let mut s = String::new();
        channel.read_to_string(&mut s)?;
        println!("{}", s);

        Ok(())
    }
}
