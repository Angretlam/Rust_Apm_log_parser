use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, prelude::*};
use std::path::Path;
use std::error::Error;

fn main() {

    // Get the file name
    let cmd_input: Vec<String> = env::args().collect();
    if cmd_input.len() == 3 {
        let in_file = &cmd_input[1];
        let out_file = &cmd_input[2];

        if parse_file(in_file.to_string()) {
            println!("File successfully parsed. Now to combine session data.");

            if consume_sessions(out_file.to_string()).is_ok() {
                println!("Successfully read the files of the sessions.");
            } else {
                println!("Files did not get condensed properly. Exiting.");

            }

        }
    } else {
        println!{"APM Parser expects and input and output location: apm_parser <in> <out>"};
    }
    
}

fn parse_file(file_handle: String) -> bool {
    // Let's read it
    let openner = File::open(file_handle).expect("Issue opening file.");
    let file_reader = BufReader::new(openner);

    // Struct
    struct LineInfo {
        prev: String
    }

    let mut prev_line = LineInfo { prev: "string".to_string() };

    // Let's write it
    for line in file_reader.lines() {

        let line_raw = line;
        if line_raw.is_ok() {

            let line_instance: String = line_raw.unwrap().to_string();
            if line_instance != prev_line.prev {

                if line_instance.contains("xlink") && ( line_instance.contains("notice tmm") || line_instance.contains("notice apm")) {
                    let line_split:Vec<&str> = line_instance.split(":").collect();
                    let session_id = line_split[7];
                    let file_path = format!("sessions/{}", session_id);

                    if std::path::Path::new(&file_path.to_string()).exists() {
                        let mut file_options = OpenOptions::new();
                        file_options.append(true);
                        file_options.write(true);

                        let output_file = file_options.open(file_path.to_string())
                            .expect("File didn't open capn");

                        let mut out_buffer = BufWriter::new(&output_file);
                        let text_holder = format!("{}{}", &line_instance, "\n");

                        out_buffer.write_all(&text_holder.as_bytes())
                            .expect("Nothing wrote to the file.");

                    } else {

                        std::fs::write(file_path.to_string(), format!("{}{}", &line_instance, "\n"))
                        .expect("Could not write a file.");                   
                    }
                }

                prev_line.prev = line_instance;
            }
        }
    }
    true
}

fn consume_sessions(output: String) -> Result<() , Box<dyn Error>> {

    std::fs::write(&output, 
        format!("Session,Session Start,Session End,User Agent,Hostname,OS,Client IP,McAfee AV Version,McAfee AV Running,McAfee AV Last Update,McAfee AV Last Scan,McAfee FW Version,McAfee FW State,McAfee DE Version,McAfee DE State,Tanium Client,Tanium State,SCCM State\n")
    ).expect("Could not write a file."); 

    struct SessionInfo {
        session: String, 
        mcafee_av_version: String,
        mcafee_av_state: String,
        mcafee_av_last_update: String,
        mcafee_av_last_scan: String,
        mcafee_fw_version: String,
        mcafee_fw_state: String, 
        mcafee_de_version: String,
        mcafee_de_state: String,
        session_start: String,
        session_ended: String,
        client_ip: String,
        hostname: String, 
        os: String, /*
        access_policy_result: String,
        connectivity_resource: String,
        webtop: String,
        username: String,*/
        user_agent: String ,
        tanium_client: String,
        tanium_status: String,
        sccm_status: String
    }

    let dir = Path::new("sessions");
    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let s_openner = File::open(&path).expect("Issue opening file.");
            let s_reader = BufReader::new(s_openner);

            let mut this_session =  SessionInfo {
                session: entry.file_name().into_string().expect("NA"),
                mcafee_av_version: "NA".to_string(),
                mcafee_av_state: "NA".to_string(),
                mcafee_av_last_update: "NA".to_string(),
                mcafee_av_last_scan: "NA".to_string(), 
                mcafee_fw_version: "NA".to_string(),
                mcafee_fw_state: "NA".to_string(),
                mcafee_de_version: "NA".to_string(),
                mcafee_de_state: "NA".to_string(),
                session_start: "NA".to_string(),
                session_ended: "NA".to_string(),
                client_ip: "NA".to_string(),
                hostname: "NA".to_string(),
                os: "NA".to_string(), /*
                access_policy_result: "NA".to_string(),
                connectivity_resource: "NA".to_string(),
                webtop: "NA".to_string(),
                username: "NA".to_string(),*/
                user_agent: "NA".to_string(),
                tanium_client: "NA".to_string(),
                tanium_status: "NA".to_string(),
                sccm_status: "NA".to_string()
            };

            for line in s_reader.lines() {
                
                if line.is_ok() {

                    let session_line: String = line.unwrap().to_string();
                    let session_parts: Vec<&str> = session_line.split(":").collect();

                    if session_line.contains("Received User-Agent") {
                        this_session.user_agent = format!("{}", &session_parts[9][1..]);

                    } else if session_line.contains("New session") {

                        struct IpInfo {
                            client: String
                        }

                        let mut ip_info = IpInfo {client: "".to_string()};

                        if &session_parts[8].chars().count() > &28 {
                            for c in session_parts[8][28..].chars() {
                                if format!("{}", c) != " " {
                                    ip_info.client = format!("{}{}", ip_info.client, c);
                                } else{
                                    break
                                }
                            }
                        }

                        this_session.client_ip = format!("{}", ip_info.client);
                        this_session.session_start = format!("{}", &session_line[..15]);

                    } else if session_line.contains("Session deleted") {
                        this_session.session_ended = format!("{}", &session_line[..15]);

                    } else if session_line.contains("Updating client info") {
                        let host_var_len: usize = session_parts[9].chars().count() - 5;
                        let os_var_len: usize = session_parts[12].chars().count() - 4;
                        this_session.hostname = format!("{}", &session_parts[9][1..host_var_len]);
                        this_session.os = format!("{}", &session_parts[12][1..os_var_len]);

                    } else if session_line.contains("av_software_check") && session_line.contains("McAfee") {
                        let av_info: Vec<&str> = session_parts[9].split(",").collect();

                        this_session.mcafee_av_version = av_info[4][8..].to_string();

                        if av_info[5].chars().count() > 6 {
                            this_session.mcafee_av_state = "Running".to_string();
                            
                        } else {
                            this_session.mcafee_av_state = "Not Running".to_string();

                        }

                        this_session.mcafee_av_last_update = av_info[11][8..].to_string();

                        if av_info[12].chars().count() > 10 {
                            this_session.mcafee_av_last_scan = av_info[12][10..].to_string();

                        } else {
                            this_session.mcafee_av_last_scan = "No scan data".to_string();

                        }
                    } else if session_line.contains("fw_software_check") && session_line.contains("McAfee") {
                        let fw_info: Vec<&str> = session_parts[9].split(",").collect();

                        this_session.mcafee_fw_version = fw_info[4][8..].to_string();

                        if fw_info[5].chars().count() > 6 {
                            this_session.mcafee_fw_state = "Running".to_string();
                            
                        } else {
                            this_session.mcafee_fw_state = "Not Running".to_string();

                        }
                    } else if session_line.contains("hd_software_check") && session_line.contains("McAfee") {
                        let de_info: Vec<&str> = session_parts[9].split(",").collect();

                        this_session.mcafee_de_version = de_info[4][8..].to_string();

                        if de_info[5].chars().count() > 6 {
                            this_session.mcafee_de_state = "Running".to_string();
                            
                        } else {
                            this_session.mcafee_de_state = "Not Running".to_string();

                        }
                    } else if session_line.contains("TaniumClient Process Check") {
                        
                        if session_line.contains("TaniumClient is running") {
                            this_session.tanium_status = "Running".to_string();

                        } else {
                            this_session.tanium_status = "Not Running".to_string();

                        }
                    } else if session_line.contains("Windows Registry") && session_line.contains("Tanium") {

                        if session_line.contains("Tanium Client Exists") {
                            this_session.tanium_client = "Installed".to_string();
                        }

                    } else if session_line.contains("CcmExec Process Check") {
                        if session_line.contains("CcmExec is running") {
                            this_session.sccm_status = "Running".to_string();
                        }

                    }
                }
            }
            // Print result
            let mut file_options = OpenOptions::new();
                file_options.append(true);
                file_options.write(true);

            let output_file = file_options.open(&output)
                .expect("File didn't open capn");

            let mut out_buffer = BufWriter::new(&output_file);
            let text_holder = format!(
                "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n", 
                this_session.session, 
                this_session.session_start, 
                this_session.session_ended, 
                this_session.user_agent, 
                this_session.hostname, 
                this_session.os,
                this_session.client_ip,
                this_session.mcafee_av_version,
                this_session.mcafee_av_state,
                this_session.mcafee_av_last_update,
                this_session.mcafee_av_last_scan,
                this_session.mcafee_fw_version,
                this_session.mcafee_fw_state,
                this_session.mcafee_de_version,
                this_session.mcafee_de_state,
                this_session.tanium_client,
                this_session.tanium_status,
                this_session.sccm_status
            );

            out_buffer.write_all(&text_holder.as_bytes())
                .expect("Nothing wrote to the file.");

            // Remove the file
            fs::remove_file(&path).expect("File removal failed.");
        }
    }
    Ok(())
}
