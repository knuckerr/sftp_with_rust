extern crate serde;
extern crate serde_json;

extern crate serde_derive;

extern crate difference;

use ssh2::{Session, Sftp};
use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::io::Read;
use std::sync::mpsc::channel;
use walkdir::WalkDir;

use std::path::Path;

use std::rc::Rc;

use indicatif::{ProgressBar, ProgressStyle};
use notify::{raw_watcher, Op, RawEvent, RecursiveMode, Watcher};

use crate::server::Server;

use chrono::Local;

use difference::{Changeset, Difference};

pub struct Event {
    path: String,
    event: notify::op::Op,
}

#[derive(Debug)]
pub struct Modified {
    filename: String,
    fullpath: String,
    modified: u64,
    size: u64,
    folder: bool,
    metadata: std::fs::Metadata,
    version: String,
}

pub fn notify(sess: Rc<Session>, path_original: &str, server: Server) -> Result<(), Box<Error>> {
    let (send, recv) = channel();
    let mut watcher = raw_watcher(send)?;
    watcher.watch(path_original, RecursiveMode::Recursive)?;
    let sftp = sess.sftp()?;
    let sftp_clone = Rc::new(sftp);
    loop {
        match recv.recv() {
            Ok(RawEvent {
                path: Some(path),
                op: Ok(op),
                cookie: _,
            }) => {
                let path = path.to_str().unwrap();
                let event = Event {
                    path: path.to_owned(),
                    event: op,
                };
                if op == Op::CLOSE_WRITE || op == Op::CREATE || op == Op::RENAME {
                    let file = File::open(path.to_owned());
                    let new_path = path.replace(path_original, &server.side_mirror);
                    if file.is_ok() {
                        let mut file = file.unwrap();
                        let is_dir = file.metadata().unwrap().is_dir();
                        if is_dir == false {
                            let mut data = Vec::new();
                            file.read_to_end(&mut data).unwrap();
                            let mut new_file = sftp_clone.create(Path::new(&new_path))?;
                            new_file.write_all(&data).unwrap();
                        } else {
                            sftp_clone.mkdir(Path::new(&new_path), 0o775)?;
                        }

                        let mut channel = sess.channel_session()?;
                        let fix_perm = format!(
                            r#"find {} -type d -exec chown www-data:www-data {{}} \;
                                       find {} -type f -exec chmod 775 {{}} \;
                                       find {} -type d -exec chmod 775 {{}} \;
                                       find {} -type f -exec chown www-data:www-data {{}} \;"#,
                            server.side_mirror,
                            server.side_mirror,
                            server.side_mirror,
                            server.side_mirror
                        );
                        channel.exec(&fix_perm)?;
                    } else {
                        sftp_clone.unlink(Path::new(&new_path))?;
                    }
                }
                if op == Op::REMOVE {
                    let new_path = path.replace(path_original, &server.side_mirror);
                    let file = sftp_clone.open(Path::new(&new_path));
                    if file.is_ok() {
                        let mut file = file.unwrap();
                        let is_dir = file.stat()?.is_dir();
                        if is_dir == false {
                            sftp_clone.unlink(Path::new(&new_path))?;
                        } else {
                            let check_remove = sftp_clone.rmdir(Path::new(&new_path));
                            if check_remove.is_ok() {
                                check_remove.unwrap();
                            } else {
                                let mut index_folder = Vec::new();
                                find_dirs(
                                    Rc::clone(&sftp_clone),
                                    &server.side_mirror,
                                    &new_path,
                                    path_original,
                                    &mut index_folder,
                                );
                                walk_sftp_folders(
                                    Rc::clone(&sftp_clone),
                                    &server.side_mirror,
                                    &new_path,
                                    path_original,
                                );

                                if !index_folder.is_empty() {
                                    for _ in index_folder {
                                        walk_sftp_folders(
                                            Rc::clone(&sftp_clone),
                                            &server.side_mirror,
                                            &new_path,
                                            path_original,
                                        );
                                    }
                                }
                                sftp_clone.rmdir(Path::new(&new_path))?;
                            }
                        }
                    }
                }
                println!("{:?} {:?}", event.path, event.event);
            }
            Ok(event) => println!("broken event: {:?}", event),
            Err(e) => println!("watch error: {:?}", e),
        }
    }
}

pub fn last_modified(
    path: &str,
    version: &str,
    exlude: Vec<String>,
) -> Result<Vec<Modified>, Box<Error>> {
    let mut files = Vec::new();
    File::open(path)?;
    for entry in WalkDir::new(path)
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let fullpath = entry.path().to_string_lossy();

        let filename = entry.file_name().to_string_lossy();
        if exlude.contains(&filename.to_string()) == false {
            let last_modified = entry.metadata()?.modified()?.elapsed()?.as_secs();
            let folder = entry.metadata()?.is_dir();

            let size = entry.metadata()?.len();
            let file = Modified {
                filename: filename.to_string(),
                fullpath: fullpath.to_string(),
                modified: last_modified,
                size: size,
                folder: folder,
                metadata: entry.metadata()?,
                version: version.to_string(),
            };
            files.push(file)
        }
    }

    Ok(files)
}

pub fn find_dirs(sftp: Rc<Sftp>, server: &str, path: &str, path1: &str, folders: &mut Vec<String>) {
    let sftp_clone = Rc::new(sftp);
    let dirs = sftp_clone.readdir(Path::new(path)).unwrap();
    for filepath in dirs {
        let remote_path = filepath.0.to_str().unwrap();
        let remote_data = filepath.1;
        if remote_data.is_dir() == true {
            folders.push(remote_path.to_owned());
            find_dirs(Rc::clone(&sftp_clone), server, remote_path, path1, folders);
        }
    }
}

pub fn walk_sftp_folders(sftp: Rc<Sftp>, server: &str, path: &str, path1: &str) {
    let sftp_clone = Rc::new(sftp);
    let dirs = sftp_clone.readdir(Path::new(path)).unwrap();
    for filepath in dirs {
        let remote_path = filepath.0.to_str().unwrap();
        let remote_data = filepath.1;
        let new_file = &remote_path.replace(&server, path1);
        let exists = File::open(new_file);
        if exists.is_err() {
            if remote_data.is_dir() == false {
                sftp_clone.unlink(Path::new(remote_path)).unwrap();
            } else {
                let dir_is_empty = sftp_clone.rmdir(Path::new(remote_path));
                if dir_is_empty.is_err() {
                    walk_sftp_folders(Rc::clone(&sftp_clone), server, remote_path, path1);
                } else {
                    dir_is_empty.unwrap();
                }
            }
        } else {
            if remote_data.is_dir() == true {
                walk_sftp_folders(Rc::clone(&sftp_clone), server, remote_path, path1);
            }
        }
    }
}

pub fn clean_old_files(sess: Rc<Session>, server: Server, path1: &str) -> Result<(), Box<Error>> {
    let sftp = sess.sftp()?;
    let sftp_clone = Rc::new(sftp);
    let dirs = sftp_clone.readdir(Path::new(&server.side_mirror));
    if dirs.is_err() {
        return Ok(());
    }
    println!("Cleaning Old files");
    walk_sftp_folders(
        Rc::clone(&sftp_clone),
        &server.side_mirror,
        &server.side_mirror,
        path1,
    );
    let mut index_folder = Vec::new();
    find_dirs(
        Rc::clone(&sftp_clone),
        &server.side_mirror,
        &server.side_mirror,
        path1,
        &mut index_folder,
    );
    if !index_folder.is_empty() {
        for _ in index_folder {
            walk_sftp_folders(
                Rc::clone(&sftp_clone),
                &server.side_mirror,
                &server.side_mirror,
                path1,
            );
        }
    }
    Ok(())
}

fn create_log(
    sess: Rc<Session>,
    local_file: &str,
    version_path: &str,
    local_data: Vec<u8>,
    remote_data: Vec<u8>,
) -> Result<(), Box<Error>> {
    if local_data == remote_data {
        return Ok(());
    }
    let sftp = sess.sftp()?;
    let path = format!("{}/{}", version_path, local_file);
    //fix the panic  casue by from_utf8.unwrap()
    let local_data = std::str::from_utf8(&local_data)?;
    let remote_data = std::str::from_utf8(&remote_data)?;

    let mut all_diff = String::new();
    let local = Local::now();
    let local = local.format("%Y-%m-%d-%H:%M:%S").to_string();
    let header = format!("Date:{}\n", local);
    all_diff.push_str(&header);
    let Changeset { diffs, .. } = Changeset::new(local_data, remote_data, "\n");
    for i in 0..diffs.len() {
        match diffs[i] {
            Difference::Add(ref x) => {
                let add = format!("OLD:[{}]\n", x);
                all_diff.push_str(&add);
            }

            Difference::Rem(ref x) => {
                let rem = format!("NEW: [{}]\n", x);
                all_diff.push_str(&rem);
            }

            Difference::Same(ref x) => {
                let same = format!("{}\n", x);
                all_diff.push_str(&same);
            }
        }
    }
    //STUPID OPEN FLAGS
    let update_file = sftp.open_mode(Path::new(&path), ssh2::READ, 0o777, ssh2::OpenType::File);
    if update_file.is_ok() {
        let mut tmp_data = Vec::new();
        let mut update_file = update_file?;
        update_file.read_to_end(&mut tmp_data)?;
        let tmp_data = std::str::from_utf8(&tmp_data)?;
        all_diff.push_str(&tmp_data);
        let update_file =
            sftp.open_mode(Path::new(&path), ssh2::WRITE, 0o777, ssh2::OpenType::File);
        let mut update_file = update_file?;
        update_file.write_all(&all_diff.as_bytes())?;
    } else {
        let mut update_file = sftp.create(Path::new(&path))?;
        update_file.write_all(&all_diff.as_bytes())?;
    }
    Ok(())
}

pub fn fix_version_path(sess: Rc<Session>, project: &str, version: &str) -> Result<(), Box<Error>> {
    let sftp = sess.sftp()?;
    let path1 = format!("/{}", project);
    let path2 = format!("/{}/versions", project);
    let path3 = format!("/{}/versions/{}", project, version);
    let paths = vec![path1, path2, path3];
    for path in paths {
        let version_path = format!("{}", path);
        let check_logs = sftp.open(Path::new(&version_path));
        if check_logs.is_err() {
            sftp.mkdir(Path::new(&version_path), 0o775)?;
        }
    }
    Ok(())
}

pub fn mirror(
    sess: Rc<Session>,
    server: Server,
    path1: &str,
    files: Vec<Modified>,
) -> Result<(), Box<Error>> {
    let sftp = sess.sftp()?;
    let check_side = sftp.opendir(Path::new(&server.side_mirror));
    if check_side.is_err() {
        sftp.mkdir(Path::new(&server.side_mirror), 0o775)?;
    }
    let version_path = format!("/{}/versions/{}", server.projectname, files[0].version);
    let check_logs = fix_version_path(Rc::clone(&sess), &server.projectname, &files[0].version);
    if check_logs.is_err() {
        eprintln!("{}", check_logs.unwrap_err());
    }
    let pb = ProgressBar::new(files.len() as u64);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
        .progress_chars("#>-"));
    println!("Start copying files");
    for file in files {
        pb.inc(1);
        let new_file = &file.fullpath.replace(path1, &server.side_mirror);
        let check_file = sftp.open(Path::new(new_file));
        if check_file.is_err() {
            if file.folder == false {
                let mut update_file = sftp.create(Path::new(&new_file))?;
                let mut data = Vec::new();
                let mut read_original = File::open(file.fullpath.to_owned())?;
                read_original.read_to_end(&mut data)?;
                update_file.write_all(&data)?;
                let mut metadata = sftp.stat(Path::new(new_file))?;
                metadata.mtime = Some(file.metadata.modified()?.elapsed()?.as_secs());
                metadata.atime = Some(file.metadata.accessed()?.elapsed()?.as_secs());
                sftp.setstat(Path::new(new_file), metadata)?;
            } else {
                sftp.mkdir(Path::new(&new_file), 0o775)?;
            }
        } else {
            let metadata = sftp.stat(Path::new(new_file))?;
            let last_modified = metadata.mtime.unwrap();
            //let size = metadata.size.unwrap();
            let mut data = Vec::new();
            if last_modified > file.modified {
                if file.folder == false {
                    let mut remote_data = Vec::new();
                    check_file.unwrap().read_to_end(&mut remote_data)?;
                    let mut old_file = File::open(file.fullpath.to_owned())?;
                    old_file.read_to_end(&mut data)?;
                    let check_log = create_log(
                        Rc::clone(&sess),
                        &file.filename,
                        &version_path,
                        data.clone(),
                        remote_data,
                    );
                    if check_log.is_err() {
                        eprintln!("{}", check_log.unwrap_err());
                    }
                    sftp.unlink(Path::new(new_file))?;
                    let mut update_file = sftp.create(Path::new(new_file))?;
                    update_file.write_all(&data)?;
                }

                //println!("OLD {}: {},{}", new_file, last_modified, size);
                //println!("NEW {}: {},{}", file.fullpath, file.modified, file.size);
            }
        }
    }
    pb.finish_with_message("Finish");
    let mut channel = sess.channel_session()?;
    let fix_perm = format!(
        r#"find {} -type d -exec chown www-data:www-data {{}} \;
                   find {} -type f -exec chmod 775 {{}} \;
                   find {} -type d -exec chmod 775 {{}} \;
                   find {} -type f -exec chown www-data:www-data {{}} \;"#,
        server.side_mirror, server.side_mirror, server.side_mirror, server.side_mirror
    );
    channel.exec(&fix_perm)?;
    Ok(())
}
