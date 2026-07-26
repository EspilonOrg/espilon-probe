Output demo/demo-bus.gif
Set Shell "bash"
Set FontSize 14
Set Width 1200
Set Height 640
Set Theme "Dracula"
Set Padding 20
Set PlaybackSpeed 1.0
Set TypingSpeed 45ms

Hide
Type "source .demo-venv/bin/activate"
Enter
Type "python3 demo/demo_bridge.py --scenario spi --port 5554 >/dev/null 2>&1 & disown"
Enter
Type "source demo/shell_setup.sh"
Enter
Type "rm -rf /tmp/probe-demo && mkdir -p /tmp/probe-demo && cd /tmp/probe-demo"
Enter
Type "export ESP_PROBE=tcp://127.0.0.1:5554 && sleep 0.8 && clear"
Enter
Show

Sleep 700ms
Type "probe spi id"
Sleep 300ms
Enter
Sleep 2000ms

Type "probe spi read --addr 0 --len 32"
Sleep 300ms
Enter
Sleep 2000ms

Type "probe spi dump --len 4096 -w flash.bin"
Sleep 300ms
Enter
Sleep 1800ms

Type "hexdump -C flash.bin | head -4"
Sleep 300ms
Enter
Sleep 3000ms

Hide
Type "pkill -f demo_bridge.py"
Enter
