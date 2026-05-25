from models.behavior import BehaviorTag

behavior = BehaviorTag(
    name="Persistence",
    reason="Registry Run key or startup indicator found",
    severity="High",
    indicators=[
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    ]
)

print(behavior.summary())
print("*" * 10)
print(behavior.to_dict())
print("*" * 10)
print(behavior.has_indicators())