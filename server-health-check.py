import datetime
import platform
import re
import subprocess
from pathlib import Path


def create_temp_dir():
    """Create C:\temp directory if it doesn't exist"""
    temp_dir = Path('C:/temp')
    if not temp_dir.exists():
        try:
            temp_dir.mkdir()
            print(f"Created directory: {temp_dir}")
        except Exception as e:
            print(f"Error creating directory {temp_dir}: {e}")
            return False
    return True


def check_disk_space():
    """Check if disk space is at least 20% free on all drives"""
    try:
        result = subprocess.run(['wmic', 'logicaldisk', 'get', 'deviceid,freespace,size'],
                                capture_output=True, text=True, check=True)
        lines = result.stdout.strip().split('\n')[1:]
        results = []

        for line in lines:
            parts = line.strip().split()
            if len(parts) >= 3 and parts[0].strip():
                try:
                    drive = parts[0].strip()
                    # Skip drives with no size information
                    if not parts[1].strip() or not parts[2].strip():
                        continue
                    free_space = float(parts[1].strip())
                    total_size = float(parts[2].strip())
                    if total_size > 0:  # Avoid division by zero
                        percent_free = (free_space / total_size) * 100
                        results.append((drive, percent_free))
                except (ValueError, IndexError) as e:
                    print(f"Warning: Could not process drive info for line: {line} - {str(e)}")

        failed_drives = [f"{drive} ({percent_free:.2f}% free)"
                         for drive, percent_free in results if percent_free < 20]

        if failed_drives:
            return False, f"Low disk space on: {', '.join(failed_drives)}"
        return True, "All drives have at least 20% free space"
    except Exception as e:
        return False, f"Error checking disk space: {str(e)}"


def check_failed_services():
    """Check for failed services"""
    try:
        result = subprocess.run(['powershell', '-Command',
                                 "Get-Service | Where-Object {$_.StartType -eq 'Automatic' -and $_.Status -ne 'Running'} | Select-Object Name"],
                                capture_output=True, text=True, check=True)
        failed_services = [line.strip() for line in result.stdout.strip().split('\n') if
                           line.strip() and not line.strip().startswith('Name')]

        if failed_services:
            return False, f"Failed services: {', '.join(failed_services)}"
        return True, "No failed services detected"
    except Exception as e:
        return False, f"Error checking services: {str(e)}"


def check_critical_events():
    """Check for critical errors in the event log (last 24 hours)"""
    try:
        # Get critical errors from the last 24 hours
        powershell_cmd = "Get-WinEvent -FilterHashtable @{LogName='Application','System'; Level=1,2; StartTime=(Get-Date).AddDays(-1)} -ErrorAction SilentlyContinue | Select-Object TimeCreated, LogName, ProviderName, Message | Format-List"
        result = subprocess.run(['powershell', '-Command', powershell_cmd],
                                capture_output=True, text=True, check=True)

        critical_events = result.stdout.strip()

        # Parse the output to count actual events rather than just checking length
        event_count = 0
        if critical_events:
            # Count sections separated by blank lines (each event)
            event_sections = [section for section in critical_events.split('\n\n') if section.strip()]
            event_count = len(event_sections)

        if event_count > 0:
            return False, f"Critical events found in the event log: {event_count} events"
        return True, "No critical events detected in the last 24 hours"
    except Exception as e:
        return False, f"Error checking event logs: {str(e)}"


def check_uptime():
    """Check if server uptime exceeds 30 days"""
    try:
        # Directly get the total days - more reliable approach
        result = subprocess.run(['powershell', '-Command',
                                 "[math]::Round(((Get-Date) - (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime).TotalDays, 1)"],
                                capture_output=True, text=True, check=True)

        try:
            days = float(result.stdout.strip())
            if days > 30:
                return False, f"Server uptime exceeds 30 days: {days:.1f} days"
            return True, f"Server uptime is within acceptable range: {days:.1f} days"
        except ValueError:
            # If direct method fails, try parsing the output format
            result = subprocess.run(['powershell', '-Command',
                                     "(Get-Date) - (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime"],
                                    capture_output=True, text=True, check=True)

            uptime_text = result.stdout.strip()

            # Try different regex patterns to find days
            days_patterns = [
                r'Days\s*:\s*(\d+)',
                r'(\d+)\s*day',
                r'(\d+)\s*d\w*'
            ]

            for pattern in days_patterns:
                days_match = re.search(pattern, uptime_text, re.IGNORECASE)
                if days_match:
                    days = int(days_match.group(1))
                    if days > 30:
                        return False, f"Server uptime exceeds 30 days: {days} days"
                    return True, f"Server uptime is within acceptable range: {days} days"

            # If we get here, we couldn't parse the days
            return False, f"Could not determine server uptime, assuming check failed. Raw data: {uptime_text[:100]}"
    except Exception as e:
        return False, f"Error checking uptime: {str(e)}"


def run_health_check():
    """Run all health checks and return results"""
    checks = {
        "Disk Space (>20% free)": check_disk_space,
        "Automatic Services Running": check_failed_services,
        "No Critical Events (24h)": check_critical_events,
        "Uptime (<30 days)": check_uptime
    }

    results = {}
    for check_name, check_func in checks.items():
        status, message = check_func()
        results[check_name] = {
            "status": "PASS" if status else "FAIL",
            "message": message
        }

    return results


def write_results_to_file(results):
    """Write health check results to file"""
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"C:/temp/server_health_check_{timestamp}.txt"

    try:
        with open(filename, 'w') as f:
            f.write(
                f"Server Health Check - {platform.node()} - {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")

            all_passed = True
            for check_name, result in results.items():
                status = result["status"]
                message = result["message"]
                if status == "FAIL":
                    all_passed = False

                f.write(f"{check_name}: {status}\n")
                f.write(f"  {message}\n\n")

            f.write("=" * 80 + "\n")
            f.write(f"Overall Status: {'PASS' if all_passed else 'FAIL'}\n")

        print(f"Results written to {filename}")
        return filename
    except Exception as e:
        print(f"Error writing results to file: {e}")
        return None


def main():
    """Main function to run the script"""
    try:
        print("Starting Windows Server Health Check...")

        # Create temp directory if needed
        if not create_temp_dir():
            print("Failed to create or access C:\temp directory. Exiting.")
            return

        # Run health checks
        results = run_health_check()

        # Write results to file
        output_file = write_results_to_file(results)

        # Display summary
        if output_file:
            print("\nHealth Check Summary:")
            for check_name, result in results.items():
                print(f"{check_name}: {result['status']}")

            # Count total passes and fails
            fail_count = sum(1 for result in results.values() if result['status'] == 'FAIL')
            print(
                f"\nOverall result: {'FAIL' if fail_count > 0 else 'PASS'} ({len(results) - fail_count}/{len(results)} checks passed)")
            print(f"Results written to: {output_file}")
    except Exception as e:
        print(f"Error in health check script: {str(e)}")
        import traceback
        print(traceback.format_exc())


if __name__ == "__main__":
    main()
