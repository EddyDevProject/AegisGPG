//! Local teams: named groups of key fingerprints, persisted in `teams.json`
//! next to the keyring. A team only references keys; it never copies them.

use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use super::{GpgError, Result};

#[derive(Clone, Serialize, Deserialize)]
pub struct Team {
    pub id: String,
    pub name: String,
    /// Uppercase hex fingerprints, in insertion order, no duplicates.
    pub members: Vec<String>,
}

pub struct TeamStore {
    path: PathBuf,
    teams: Mutex<Vec<Team>>,
}

fn normalize(members: Vec<String>) -> Result<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for m in members {
        let fp = m.trim().to_uppercase();
        if fp.is_empty() || !fp.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(GpgError::InvalidInput("Invalid key fingerprint".into()));
        }
        if !out.contains(&fp) {
            out.push(fp);
        }
    }
    Ok(out)
}

impl TeamStore {
    pub fn open(dir: PathBuf) -> Self {
        let path = dir.join("teams.json");
        let teams = fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        Self { path, teams: Mutex::new(teams) }
    }

    pub fn list(&self) -> Vec<Team> {
        let mut v = self.teams.lock().unwrap().clone();
        v.sort_by_key(|t| t.name.to_lowercase());
        v
    }

    /// Creates the team when `id` is `None`, otherwise replaces name and members.
    pub fn save(&self, id: Option<String>, name: String, members: Vec<String>) -> Result<Team> {
        let name = name.trim().to_string();
        if name.is_empty() {
            return Err(GpgError::InvalidInput("Team name is required".into()));
        }
        let members = normalize(members)?;
        let mut teams = self.teams.lock().unwrap();
        if teams
            .iter()
            .any(|t| t.name.eq_ignore_ascii_case(&name) && Some(&t.id) != id.as_ref())
        {
            return Err(GpgError::InvalidInput(format!("A team named \"{name}\" already exists")));
        }
        let team = match id {
            Some(id) => {
                let t = teams
                    .iter_mut()
                    .find(|t| t.id == id)
                    .ok_or_else(|| GpgError::NotFound("team".into()))?;
                t.name = name;
                t.members = members;
                t.clone()
            }
            None => {
                let nanos = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0);
                let t = Team { id: format!("{nanos:x}"), name, members };
                teams.push(t.clone());
                t
            }
        };
        self.persist(&teams)?;
        Ok(team)
    }

    pub fn delete(&self, id: &str) -> Result<()> {
        let mut teams = self.teams.lock().unwrap();
        let before = teams.len();
        teams.retain(|t| t.id != id);
        if teams.len() == before {
            return Err(GpgError::NotFound("team".into()));
        }
        self.persist(&teams)
    }

    fn persist(&self, teams: &[Team]) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(teams).map_err(|e| GpgError::Other(e.to_string()))?;
        let tmp = self.path.with_extension("tmp");
        fs::write(&tmp, bytes)?;
        fs::rename(tmp, &self.path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> TeamStore {
        let dir = std::env::temp_dir().join(format!("aegis-teams-{:?}", std::thread::current().id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        TeamStore::open(dir)
    }

    #[test]
    fn create_update_delete_roundtrip() {
        let s = store();
        let t = s.save(None, " Dev ".into(), vec!["ab12".into(), "AB12".into(), "cd34".into()]).unwrap();
        assert_eq!(t.name, "Dev");
        assert_eq!(t.members, vec!["AB12", "CD34"]);
        assert!(s.save(None, "dev".into(), vec![]).is_err());
        s.save(Some(t.id.clone()), "Dev2".into(), vec!["EF56".into()]).unwrap();
        assert_eq!(TeamStore::open(s.path.parent().unwrap().to_path_buf()).list()[0].members, vec!["EF56"]);
        s.delete(&t.id).unwrap();
        assert!(s.list().is_empty());
    }

    #[test]
    fn rejects_bad_fingerprints() {
        assert!(store().save(None, "x".into(), vec!["../etc".into()]).is_err());
    }
}
