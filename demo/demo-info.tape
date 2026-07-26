Output demo/demo-info.gif
Set Shell "bash"
Set FontSize 14
Set Width 1200
Set Height 840
Set Theme "Dracula"
Set Padding 20
Set PlaybackSpeed 1.0
Set TypingSpeed 45ms

Hide
Type "source .demo-venv/bin/activate"
Enter
Type "python3 demo/demo_bridge.py --scenario info --port 5551 >/dev/null 2>&1 & disown"
Enter
Type "source demo/shell_setup.sh"
Enter
Type "export ESP_PROBE=tcp://127.0.0.1:5551 && sleep 0.8 && clear"
Enter
Show

Sleep 800ms
Type "probe --help"
Sleep 400ms
Enter
Sleep 3500ms

Type "probe info"
Sleep 400ms
Enter
Sleep 3500ms

Hide
Type "pkill -f demo_bridge.py"
Enter
