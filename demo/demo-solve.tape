Output demo/demo-solve.gif
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
Type "python3 demo/demo_bridge.py --scenario solve --port 5555 >/dev/null 2>&1 & disown"
Enter
Type "source demo/shell_setup.sh"
Enter
Type "export ESP_PROBE=tcp://127.0.0.1:5555 && sleep 0.8 && clear"
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
Sleep 2000ms

Type "probe gatt read 0x0011"
Sleep 300ms
Enter
Sleep 1600ms

Type "probe gatt write 0x0014 c0ffee"
Sleep 300ms
Enter
Sleep 1600ms

Type "probe gatt read 0x0011"
Sleep 400ms
Enter
Sleep 3500ms

Hide
Type "pkill -f demo_bridge.py"
Enter
