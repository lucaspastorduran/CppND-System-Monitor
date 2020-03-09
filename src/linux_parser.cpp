#include <dirent.h>
#include <unistd.h>
#include <string>
#include <sstream>
#include <vector>

#include "linux_parser.h"

using std::stof;
using std::string;
using std::to_string;
using std::vector;

template <typename T>
T readValueFromFile(const std::string &path, const std::string &argumentName) {
  T value;
  std::ifstream filestream(path);

  if (filestream.is_open()) {
    std::string line;
    
    while (std::getline(filestream, line)) {
      std::istringstream lineStream(line);
      std::string argument;
      lineStream >> argument;
      
      if (argument == argumentName) {
        lineStream >> value;
        return value;
      }
    }
  }

  return value;
}

// DONE: An example of how to read data from the filesystem
string LinuxParser::OperatingSystem() {
  string line;
  string key;
  string value;
  std::ifstream filestream(kOSPath);
  if (filestream.is_open()) {
    while (std::getline(filestream, line)) {
      std::replace(line.begin(), line.end(), ' ', '_');
      std::replace(line.begin(), line.end(), '=', ' ');
      std::replace(line.begin(), line.end(), '"', ' ');
      std::istringstream linestream(line);
      while (linestream >> key >> value) {
        if (key == "PRETTY_NAME") {
          std::replace(value.begin(), value.end(), '_', ' ');
          return value;
        }
      }
    }
  }
  return value;
}

// DONE: An example of how to read data from the filesystem
string LinuxParser::Kernel() {
  string os, version, kernel;
  string line;
  std::ifstream stream(kProcDirectory + kVersionFilename);
  if (stream.is_open()) {
    std::getline(stream, line);
    std::istringstream linestream(line);
    linestream >> os >> version >> kernel;
  }
  return kernel;
}

// BONUS: Update this to use std::filesystem
vector<int> LinuxParser::Pids() {
  vector<int> pids;
  DIR* directory = opendir(kProcDirectory.c_str());
  struct dirent* file;
  while ((file = readdir(directory)) != nullptr) {
    // Is this a directory?
    if (file->d_type == DT_DIR) {
      // Is every character of the name a digit?
      string filename(file->d_name);
      if (std::all_of(filename.begin(), filename.end(), isdigit)) {
        int pid = stoi(filename);
        pids.push_back(pid);
      }
    }
  }
  closedir(directory);
  return pids;
}

// TODO: Read and return the system memory utilization
float LinuxParser::MemoryUtilization() { 
  float totalMemory = 0.0f;
  float freeMemory = 0.0f;
 
  std::ifstream filestream(kProcDirectory + kMeminfoFilename);
  if (filestream.is_open()) {
    std::string line;
    std::string argument;
    
    if (std::getline(filestream, line)) {
      std::istringstream linestream(line);
      if ((linestream >> argument) && argument == "MemTotal:") {
        linestream >> totalMemory;
      }
    }
    
    if (std::getline(filestream, line)) {
      std::istringstream linestream(line);
      if ((linestream >> argument) && argument == "MemFree:") {
        linestream >> freeMemory;
      }
    }
  }

  float usedMemory = totalMemory - freeMemory;
  return totalMemory == 0.0 ? 0.0 : (usedMemory/totalMemory);
}

// TODO: Read and return the system uptime
long LinuxParser::UpTime() { 
  long uptimeInSeconds = 0; 
  
  std::ifstream filestream(kProcDirectory + kUptimeFilename);
  if (filestream.is_open()) {
    filestream >> uptimeInSeconds;
  }

  return uptimeInSeconds;
}

// TODO: Read and return the number of jiffies for the system
long LinuxParser::Jiffies() { return 0; }

// TODO: Read and return the number of active jiffies for a PID
// REMOVE: [[maybe_unused]] once you define the function
long LinuxParser::ActiveJiffies(int pid[[maybe_unused]]) { return 0; }

// TODO: Read and return the number of active jiffies for the system
long LinuxParser::ActiveJiffies() { 
  std::vector <long> cpuJiffies = CpuUtilization();
  
  return cpuJiffies[kUser_] + cpuJiffies[kNice_] + cpuJiffies[kSystem_] + 
         cpuJiffies[kIRQ_] + cpuJiffies[kSoftIRQ_] + cpuJiffies[kSteal_];
}

// TODO: Read and return the number of idle jiffies for the system
long LinuxParser::IdleJiffies() { 
  std::vector <long> cpuJiffies = CpuUtilization();
  return cpuJiffies[kIdle_] + cpuJiffies[kIOwait_];
}

// TODO: Read and return CPU utilization
vector<long> LinuxParser::CpuUtilization() { 
  std::vector<long> cpuJiffies;
  
  std::ifstream filestream(kProcDirectory + kStatFilename);
  if (filestream.is_open()) {
    std::string cpu;
    filestream >> cpu;
    if (cpu == "cpu") {
      for (int i = 0; i < CPUStates::END; i++) {
        long value;
        filestream >> value;
        cpuJiffies.push_back(value);
      }
    }
  }

  return cpuJiffies;
}

// TODO: Read and return the total number of processes
int LinuxParser::TotalProcesses() { 
  int numberProcesses = 0; 
  std::string path(kProcDirectory + kStatFilename);

  numberProcesses = readValueFromFile <int> (path, "processes");
  return numberProcesses;
}

// TODO: Read and return the number of running processes
int LinuxParser::RunningProcesses() { 
  int processesRunning = 0; 
  std::string path(kProcDirectory + kStatFilename);

  processesRunning = readValueFromFile <int> (path, "procs_running");
  return processesRunning;
 }

// TODO: Read and return the command associated with a process
// REMOVE: [[maybe_unused]] once you define the function
string LinuxParser::Command(int pid[[maybe_unused]]) { return string(); }

// TODO: Read and return the memory used by a process
// REMOVE: [[maybe_unused]] once you define the function
string LinuxParser::Ram(int pid[[maybe_unused]]) { return string(); }

// TODO: Read and return the user ID associated with a process
// REMOVE: [[maybe_unused]] once you define the function
string LinuxParser::Uid(int pid) { 
  std::string userId = "No One";
  std::stringstream processPath;
  processPath << kProcDirectory << pid << kStatusFilename;

  userId = readValueFromFile <std::string> (processPath.str(), "Uid:");
  return userId;
}

// TODO: Read and return the user associated with a process
// REMOVE: [[maybe_unused]] once you define the function
string LinuxParser::User(int pid[[maybe_unused]]) { return string(); }

// TODO: Read and return the uptime of a process
// REMOVE: [[maybe_unused]] once you define the function
long LinuxParser::UpTime(int pid[[maybe_unused]]) { return 0; }