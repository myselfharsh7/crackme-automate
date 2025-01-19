import angr
import unicorn

def solve_crackme(binary_path, success_message, failure_message):
    """
    Automates solving a crackme binary by finding the correct input using symbolic execution.
    Args:
        binary_path (str): Path to the binary file.
        success_message (str): Success message to identify the correct input.
        failure_message (str): Failure message to avoid incorrect paths.
    """
    print(f"[+] Loading binary: {binary_path}")
    project = angr.Project(binary_path, load_options={"auto_load_libs": False})

    # Define the entry point and target addresses
    start_state = project.factory.entry_state()
    simulation_manager = project.factory.simulation_manager(start_state)

    # Specify target and avoid addresses
    def is_successful(state):
        stdout_output = state.posix.dumps(1)  # Output written to stdout
        return success_message.encode() in stdout_output

    def should_avoid(state):
        stdout_output = state.posix.dumps(1)
        return failure_message.encode() in stdout_output

    print("[+] Running symbolic execution...")
    simulation_manager.explore(find=is_successful, avoid=should_avoid)

    if simulation_manager.found:
        solution_state = simulation_manager.found[0]
        solution = solution_state.posix.dumps(0).decode()  # Input that solves the binary
        print(f"[+] Solution found: {solution}")
        return solution
    else:
        print("[-] No solution found.")
        return None

if __name__ == "__main__":
    # Get user input for binary path and success/failure messages
    binary_path = input("Enter the path to the crackme binary: ").strip()
    success_message = input("Enter the success message to look for: ").strip()
    failure_message = input("Enter the failure message to avoid: ").strip()

    try:
        solution = solve_crackme(binary_path, success_message, failure_message)
        if solution:
            print(f"Input to solve the crackme: {solution}")
        else:
            print("Failed to solve the crackme.")
    except Exception as e:
        print(f"[-] An error occurred: {e}")
