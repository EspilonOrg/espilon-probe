Output demo/demo-scan-sniff.gif
Set Shell "bash"
Set FontSize 14
Set Width 1200
Set Height 660
Set Theme "Dracula"
Set Padding 20
Set PlaybackSpeed 1.0
Set TypingSpeed 45ms

Hide
Type "source .demo-venv/bin/activate"
Enter
Type "python3 demo/demo_bridge.py --scenario zigbee --port 5552 >/dev/null 2>&1 & disown"
Enter
Type "source demo/shell_setup.sh"
Enter
Type "rm -rf /tmp/probe-demo && mkdir -p /tmp/probe-demo && cd /tmp/probe-demo"
Enter
Type "export ESP_PROBE=tcp://127.0.0.1:5552 && sleep 0.8 && clear"
Enter
Show

Sleep 700ms
Type "probe info"
Sleep 300ms
Enter
Sleep 1800ms

Type "probe scan"
Sleep 300ms
Enter
Sleep 2500ms

Type "probe sniff -w capture.pcap -c 8"
Sleep 300ms
Enter
Sleep 2000ms

Type "file capture.pcap"
Sleep 300ms
Enter
Sleep 3000ms

Hide
Type "pkill -f demo_bridge.py"
Enter
