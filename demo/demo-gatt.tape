Output demo/demo-gatt.gif
Set Shell "bash"
Set FontSize 14
Set Width 1200
Set Height 600
Set Theme "Dracula"
Set Padding 20
Set PlaybackSpeed 1.0
Set TypingSpeed 45ms

Hide
Type "source .demo-venv/bin/activate"
Enter
Type "python3 demo/demo_bridge.py --scenario gatt --port 5553 >/dev/null 2>&1 & disown"
Enter
Type "source demo/shell_setup.sh"
Enter
Type "export ESP_PROBE=tcp://127.0.0.1:5553 && sleep 0.8 && clear"
Enter
Show

Sleep 700ms
Type "probe scan"
Sleep 300ms
Enter
Sleep 2000ms

Type "probe gatt enum"
Sleep 300ms
Enter
Sleep 2200ms

Type "probe gatt read 0x0011"
Sleep 300ms
Enter
Sleep 1800ms

Type "probe gatt write 0x0014 01"
Sleep 300ms
Enter
Sleep 1800ms

Type "probe gatt read 0x0011"
Sleep 300ms
Enter
Sleep 3000ms

Hide
Type "pkill -f demo_bridge.py"
Enter
