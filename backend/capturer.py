import asyncio
import collections
import datetime
import os

class PacketCapturer:
    def __init__(self, interface="wlan0", captures_dir="captures"):
        self.interface = interface
        self.captures_dir = captures_dir
        if not os.path.exists(self.captures_dir):
            os.makedirs(self.captures_dir)

    async def capture_for_ip(self, ip, duration=10):
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"capture_{ip.replace('.', '_')}_{timestamp}.pcap"
        filepath = os.path.join(self.captures_dir, filename)

        # 1. Capture to file
        capture_cmd = [
            "tshark", "-i", self.interface,
            "-f", f"host {ip}",
            "-a", f"duration:{duration}",
            "-w", filepath
        ]

        try:
            # Run capture
            proc = await asyncio.create_subprocess_exec(*capture_cmd)
            await proc.wait()

            # 2. Analyze the saved file for summary
            analyze_cmd = [
                "tshark", "-r", filepath,
                "-T", "fields",
                "-e", "_ws.col.Protocol",
                "-e", "frame.len"
            ]
            
            proc_analyze = await asyncio.create_subprocess_exec(
                *analyze_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc_analyze.communicate()

            # Parse results
            lines = stdout.decode().strip().split('\n')
            protocols = collections.Counter()
            total_bytes = 0
            packet_count = 0

            if lines and lines != ['']:
                for line in lines:
                    parts = line.split('\t')
                    if len(parts) >= 2:
                        proto = parts[0].strip() or "Unknown"
                        try:
                            size = int(parts[1].strip() or 0)
                        except: size = 0
                        protocols[proto] += 1
                        total_bytes += size
                        packet_count += 1

            return {
                "total_packets": packet_count,
                "total_bytes": total_bytes,
                "protocols": dict(protocols),
                "ip": ip,
                "duration": duration,
                "filename": filename,
                "file_path": filepath
            }

        except Exception as e:
            return {"error": str(e)}

        except Exception as e:
            return {"error": str(e)}

if __name__ == "__main__":
    # Test
    capturer = PacketCapturer()
    loop = asyncio.get_event_loop()
    res = loop.run_until_complete(capturer.capture_for_ip("127.0.0.1", 2))
    print(res)
