void enforcePermission();
void hasPermission();
void doThing();

void GoodOverride() {
    enforcePermission();
    doThing();
}

void BadOverride() {
    doThing();
}

void GuardedOverride() {
    if (!hasPermission()) {
        return;
    }
    doThing();
}
