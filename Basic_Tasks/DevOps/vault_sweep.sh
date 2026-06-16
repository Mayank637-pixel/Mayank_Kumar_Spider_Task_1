#!/bin/bash

echo "Vault Sweep Starting"
target_dir="$1"
dangerous_patterns=(
    "shutdown"
    "rm -rf"
    "reboot"
    "mkfs"
)

sensitive_keys=(
    "PASSWORD"
    "TOKEN"
    "SECRET"
)

if [ -z "$target_dir" ]
then
echo "No directory provided"
echo "Usage: ./vault_sweep.sh <directory>"
exit 1
fi
if [ ! -d "$target_dir" ]
then
echo "provided directory does not exit , please provide a valid one"
exit 1
fi
 
echo "Target dir is $target_dir"

log_message() {
level="$1"
message="$2"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message " >> vault_sweep.log
chmod 600 vault_sweep.log
}
log_message "INFO" "Vault Sweep Started"

for file in $(find $target_dir -type f -name "*.sh")
do
 echo "checking '$file'"
 log_message "INFO" "Scanning $file"
 for dag_command in "${dangerous_patterns[@]}"
 do
  if grep -q "$dag_command" "$file"
  then
  echo "[WARNING] dangerous command: $dag_command found in $file"
  log_message "WARN" "$file contain dengerous command $dag_command "
  fi
 done
 permissions=$(stat -c "%A" "$file")
 if [[ "$permissions" == *w? ]] 
 then
 echo "[WARN] $file is world writable"
 log_message "WARNING" "$file is world writable"
 read -p "Dou you want to change writable permission: (y/n) " user_input
 if [ "$user_input" == "y" ]
 then
 chmod o-w "$file"
 echo "[FIX] Removed world writable permission from $file"
 log_message "FIX" "Removed world writable permission from $file"
 else
 echo "$file still has writable permision"
 log_message "WARN" "$file still has writable permision"
 fi
 fi
 if grep -Eq "curl.*\|.*sh" "$file"
 then
 echo "[WARN] $file contains curl | sh"
 log_message "WARN" "$file contains curl | sh"
 fi
 if grep -Eq "wget.*\|.*bash" "$file"
 then
 echo "[WARN] $file contains wget | bash"
 log_message "WARN" "$file contains wget | bash"
 fi
 
 
 
done  
for env_file in $(find $target_dir -type f -name ".env*"  ! -name "*.sanitized")
do
 echo "Processing env file: $env_file"
 log_message "INFO" "Processing env file $env_file"
 sanitized_file="${env_file}.sanitized"
 >"$sanitized_file"
 while read -r line
 do
  is_sansitive=0	 
  
  if [[ "$line" =~ ^[A-Z0-9_]+=.*$ ]]
  then
  for key in "${sensitive_keys[@]}"
  do 
    if [[ "$line" == *"$key"* ]]
    then
     echo "Sensitive line found $line" 
     log_message "SKIP" "Rejected: $line"
     is_sansitive=1
     break
     fi
   done  
    if [[ "$is_sansitive" == 1 ]]
    then
    
    continue
    fi
    if [[ "$line" == "PATH="* ]]
    then
    echo "[SKIP] Rejected: $line"
    log_message "SKIP" "Rejected: $line"
    continue
    fi 
    
    echo "$line" >> "$sanitized_file"
     
     
  fi
 done < "$env_file" 
 
done  

 





