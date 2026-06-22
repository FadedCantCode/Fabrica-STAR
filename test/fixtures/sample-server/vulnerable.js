// Intentionally vulnerable sample server, used only as a test fixture.
import { exec, spawn } from "node:child_process";

export function runUserCommand(userInput) {
  // command injection: untrusted input concatenated into a shell string
  exec("echo " + userInput, (err, stdout) => console.log(stdout));
}

export function runWithShell(cmd) {
  spawn(cmd, { shell: true });
}

export function evaluate(expr) {
  return eval(expr);
}

export async function fetchRemote(target) {
  return fetch(`https://api.example.com/${target}`);
}

const apiKey = "sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
