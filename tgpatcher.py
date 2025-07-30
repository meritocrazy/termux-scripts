#!/data/data/com.termux/files/usr/bin/python3
"""
Telegram Patcher - Smali Patching Tool for Termux
@author: Abhi (@AbhiTheModder), Improved by Assistant
Patch Credits: @Zylern_OP, @rezaAa1177, @AbhiTheModder, Nekogram
"""

import argparse
import os
import re
import sys
from pathlib import Path
from typing import List, Optional, Callable, Tuple, Dict, Union

# ANSI Colors
RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
BLUE = "\033[0;34m"
NC = "\033[0m"  # No Color

# Hook Smali Code (Injected for Anti-Delete)
HOOK_SMALI = '''\
.class public Lorg/telegram/abhi/Hook;
.super Ljava/lang/Object;
.source "SourceFile"

# static fields
.field public static candelMessages:Z

# direct methods
.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public static hook()V
    .registers 1
    const/4 v0, 0x1
    invoke-static {v0}, Lorg/telegram/abhi/Hook;->setCanDelMessages(Z)V
    return-void
.end method

.method public static setCanDelMessages(Z)V
    .registers 4
    sput-boolean p0, Lorg/telegram/abhi/Hook;->candelMessages:Z
    sget-object v0, Lorg/telegram/messenger/ApplicationLoader;->applicationContext:Landroid/content/Context;
    const-string v1, "mainconfig"
    const/4 v2, 0x0
    invoke-virtual {v0, v1, v2}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;
    move-result-object v0
    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;
    move-result-object v0
    const-string v1, "candelMessages"
    invoke-interface {v0, v1, p0}, Landroid/content/SharedPreferences$Editor;->putBoolean(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;
    move-result-object v0
    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V
    return-void
.end method

.method public static unhook()V
    .registers 1
    sget-boolean v0, Lorg/telegram/abhi/Hook;->candelMessages:Z
    if-eqz v0, :cond_8
    const/4 v0, 0x0
    invoke-static {v0}, Lorg/telegram/abhi/Hook;->setCanDelMessages(Z)V
    :cond_8
    return-void
.end method
'''

class NoMethodFoundError(Exception):
    """Raised when a method is not found during patching."""
    pass


def log_info(msg: str) -> None:
    print(f"{GREEN}INFO:{NC} {msg}")

def log_warn(msg: str) -> None:
    print(f"{YELLOW}WARN:{NC} {msg}")

def log_error(msg: str) -> None:
    print(f"{RED}ERROR:{NC} {msg}")

def log_step(msg: str) -> None:
    print(f"{YELLOW}START:{NC} {msg}")


def find_smali_file(root_dir: Path, filename: str) -> Optional[Path]:
    """Recursively find a file by name."""
    for path in root_dir.rglob(filename):
        if path.is_file():
            return path
    return None


def find_smali_file_by_method(root_dir: Path, method_signature: str) -> Optional[Path]:
    """Find a smali file containing a given method signature."""
    pattern = re.compile(rf"\.method\s+.*{re.escape(method_signature)}")
    for smali in root_dir.rglob("*.smali"):
        try:
            with smali.open("r", encoding="utf-8") as f:
                if pattern.search(f.read()):
                    return smali
        except (IOError, UnicodeDecodeError) as e:
            log_warn(f"Skipped {smali}: {e}")
    return None


def read_lines(file_path: Path) -> List[str]:
    """Safely read file lines."""
    try:
        return file_path.read_text(encoding="utf-8").splitlines(keepends=True)
    except Exception as e:
        raise IOError(f"Failed to read {file_path}: {e}")


def write_lines(file_path: Path, lines: List[str]) -> None:
    """Safely write lines to file."""
    try:
        file_path.write_text("".join(lines), encoding="utf-8")
    except Exception as e:
        raise IOError(f"Failed to write {file_path}: {e}")


def modify_method(file_path: Path, method_sig: str, new_code: List[str]) -> None:
    """
    Replace a method in a smali file.
    """
    lines = read_lines(file_path)
    in_method = False
    new_lines = []
    method_found = False

    for line in lines:
        if f".method {method_sig}" in line:
            in_method = True
            method_found = True
            new_lines.extend(new_code)
            continue
        if in_method and ".end method" in line:
            in_method = False
            continue
        if not in_method:
            new_lines.append(line)

    if not method_found:
        raise NoMethodFoundError(f"Method '{method_sig}' not found in {file_path}")

    write_lines(file_path, new_lines)
    log_info(f"Modified method: {method_sig}")


def modify_method_preserve_annotations(file_path: Path, method_sig: str, new_code: List[str]) -> None:
    """
    Modify a method but preserve annotations before injecting code after them.
    """
    lines = read_lines(file_path)
    in_method = False
    in_annotation = False
    method_found = False
    annotation_end_idx = -1
    new_lines = []

    for i, line in enumerate(lines):
        if f".method {method_sig}" in line:
            in_method = True
            method_found = True
            new_lines.append(line)
            continue

        if in_method:
            if ".annotation" in line:
                in_annotation = True
            elif in_annotation and ".end annotation" in line:
                in_annotation = False
                annotation_end_idx = i

            new_lines.append(line)

            if not in_annotation and annotation_end_idx != -1 and i > annotation_end_idx:
                new_lines.extend(new_code)
                annotation_end_idx = -1  # Prevent re-injection

            if ".end method" in line:
                in_method = False
        else:
            new_lines.append(line)

    if not method_found:
        raise NoMethodFoundError(f"Method '{method_sig}' not found in {file_path}")

    write_lines(file_path, new_lines)
    log_info(f"Modified (with annotations preserved): {method_sig}")


def copy_method(file_path: Path, src_method: str, dst_method: str) -> None:
    """Copy a method and rename it."""
    lines = read_lines(file_path)
    in_method = False
    method_lines = []
    method_found = False

    for line in lines:
        if f".method {src_method}" in line:
            in_method = True
            method_found = True
            method_lines.append(line.replace(src_method, dst_method))
            continue
        if in_method:
            method_lines.append(line)
            if ".end method" in line:
                in_method = False

    if not method_found:
        log_warn(f"Method '{src_method}' not found in {file_path}")
        return

    file_path.write_text("".join(lines + method_lines), encoding="utf-8")
    log_info(f"Copied method '{src_method}' → '{dst_method}'")


def apply_regex_patch(
    root_dir: Path,
    search_pattern: str,
    replace_pattern: str,
    target_file: Optional[Path] = None
) -> None:
    """Apply regex-based patch to one or all smali files."""
    pattern = re.compile(search_pattern)
    files = [target_file] if target_file else root_dir.rglob("*.smali")

    for file_path in files:
        if not file_path.is_file():
            continue
        try:
            content = file_path.read_text(encoding="utf-8")
            new_content = pattern.sub(replace_pattern, content)
            if new_content != content:
                file_path.write_text(new_content, encoding="utf-8")
                log_info(f"Applied regex patch to {file_path}")
        except Exception as e:
            log_warn(f"Failed to patch {file_path}: {e}")


# === PATCH FUNCTIONS ===

def apply_isRestrictedMessage(root_dir: Path) -> None:
    pat = r"(iget-boolean\s+([vp]\d+),\s+([vp]\d+),\s+Lorg/telegram/[^;]+;->isRestrictedMessage:Z)"
    repl = r"\1\nconst/4 \2, 0x0"
    apply_regex_patch(root_dir, pat, repl)

def apply_enableSavingMedia(root_dir: Path) -> None:
    pat = r"(iget-boolean\s+([vp]\d+),\s+([vp]\d+),\s+Lorg/telegram/[^;]+;->noforwards:Z)"
    repl = r"\1\nconst/4 \2, 0x0"
    apply_regex_patch(root_dir, pat, repl)

def apply_premiumLocked(root_dir: Path) -> None:
    pat = r"(iget-boolean\s+([vp]\d+),\s+([vp]\d+),\s+Lorg/telegram/[^;]+;->premiumLocked:Z)"
    repl = r"\1\nconst/4 \2, 0x0"
    apply_regex_patch(root_dir, pat, repl)

def apply_EnableScreenshots(root_dir: Path) -> None:
    flag_pat = r"Landroid/view/Window;->.*Flags"
    const_pat = r"const/16 (v\d+), 0x2000"
    repl = r"const/16 \1, 0x0"
    for file in root_dir.rglob("*.smali"):
        try:
            content = file.read_text()
            if re.search(flag_pat, content):
                new_content = re.sub(const_pat, repl, content)
                if new_content != content:
                    file.write_text(new_content)
                    log_info(f"Applied windowFlags patch: {file}")
        except:
            pass

def apply_EnableScreenshots2(root_dir: Path) -> None:
    pat1 = r"(sget-boolean\s+([vp]\d+).*SharedConfig;->allowScreenCapture:Z)"
    repl1 = r"\1\nconst/4 \2, 0x1"
    pat2 = r"(iget-boolean\s+([vp]\d+),\s+([vp]\d+),\s+Lorg/telegram/ui/[^;]+;->allowScreenshots:Z)"
    repl2 = r"\1\nconst/4 \2, 0x1"
    for file in root_dir.rglob("*.smali"):
        try:
            content = file.read_text()
            new_content = re.sub(pat1, repl1, content)
            new_content = re.sub(pat2, repl2, new_content)
            if new_content != content:
                file.write_text(new_content)
                log_info(f"Applied allowScreenCapture patch: {file}")
        except:
            pass

def apply_EnableScreenshots3(root_dir: Path) -> None:
    pat = r"or-int/lit16\s+([vp]\d+),\s+([vp]\d+),\s+0x2000"
    repl = r"or-int/lit16 \1, \1, 0x0"
    for fname in ["SecretMediaViewer.smali", "PhotoViewer.smali"]:
        fpath = find_smali_file(root_dir, fname)
        if fpath:
            apply_regex_patch(root_dir, pat, repl, fpath)


def modify_isPremium(file_path: Path) -> None:
    code = [
        ".method public isPremium()Z\n",
        "    .locals 1\n",
        "    const/4 v0, 0x1\n",
        "    return v0\n",
        ".end method\n"
    ]
    try:
        modify_method(file_path, "public isPremium()Z", code)
    except NoMethodFoundError as e:
        log_warn(str(e))


def modify_markMessagesAsDeleted(file_path: Path) -> None:
    root_dir = file_path.parent.parent
    smali_dir = root_dir / "smali"
    if not (root_dir / "archive-info.json").exists():
        smali_dir = root_dir / "smali_classes2"  # fallback

    hook_dir = smali_dir / "org" / "telegram" / "abhi"
    hook_dir.mkdir(parents=True, exist_ok=True)
    (hook_dir / "Hook.smali").write_text(HOOK_SMALI, encoding="utf-8")

    # Regex patches
    apply_regex_patch(root_dir, r"sget\s+([vp]\d+),\s+Lorg/telegram/messenger/R\$string;->ShowAds:I(\n.*?goto\s+:goto_\d+)?", 
                      r'const-string \1, "Do Not Delete Messages"')
    apply_regex_patch(root_dir, r"sget\s+([vp]\d+),\s+Lorg/telegram/messenger/R\$string;->ShowAdsInfo:I(\n.*?goto\s+:goto_\d+)?",
                      r'const-string \1, "After enabling, revisit this page. Mod by Abhi"')
    apply_regex_patch(root_dir, r"sget\s+([vp]\d+),\s+Lorg/telegram/messenger/R\$string;->ShowAdsTitle:I(\n.*?goto\s+:goto_\d+)?",
                      r'const-string \1, "Anti-Delete Messages"\n    invoke-virtual {v1, \1}, Lorg/telegram/ui/Cells/HeaderCell;->setText(Ljava/lang/CharSequence;)V\n    return-void')

    # Copy and modify TextCell
    textcell = find_smali_file(root_dir, "TextCell.smali")
    if textcell:
        copy_method(textcell, "public setTextAndCheck(Ljava/lang/CharSequence;ZZ)V",
                    "public setTextAndCheck2(Ljava/lang/CharSequence;ZZ)V")
        _modify_textcell_for_toggle(textcell)

    # Modify LaunchActivity onCreate
    launch = find_smali_file(root_dir, "LaunchActivity.smali")
    if launch:
        _inject_prefs_to_oncreate(launch)

    # Inject checks into markMessagesAsDeleted
    try:
        modify_method_preserve_annotations(file_path, "public markMessagesAsDeleted(JIZZ)Ljava/util/ArrayList;", [
            "    sget-boolean v0, Lorg/telegram/abhi/Hook;->candelMessages:Z\n",
            "    if-eqz v0, :cond_7\n",
            "    const/4 p1, 0x0\n",
            "    return-object p1\n",
            "    :cond_7\n"
        ])
    except NoMethodFoundError as e:
        log_warn(str(e))

    try:
        modify_method_preserve_annotations(file_path, "public markMessagesAsDeleted(JLjava/util/ArrayList;ZZII)Ljava/util/ArrayList;", [
            "    sget-boolean v0, Lorg/telegram/abhi/Hook;->candelMessages:Z\n",
            "    if-eqz v0, :cond_7\n",
            "    const/4 v1, 0x0\n",
            "    return-object v1\n",
            "    :cond_7\n"
        ])
    except NoMethodFoundError as e:
        log_warn(str(e))


def _modify_textcell_for_toggle(file_path: Path) -> None:
    lines = read_lines(file_path)
    new_lines = []
    in_method = False
    method_sig = "public setTextAndCheck2(Ljava/lang/CharSequence;ZZ)V"

    for line in lines:
        if f".method {method_sig}" in line:
            in_method = True
            new_lines.append(line)
            continue
        if in_method:
            new_lines.append(line)
            if "return-void" in line:
                new_lines.extend([
                    "    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;\n",
                    "    move-result-object v1\n",
                    '    const-string v0, "Turned off"\n',
                    "    if-eqz p2, :cond_48\n",
                    '    const-string v0, "Turned on"\n',
                    "    :cond_48\n",
                    "    invoke-static {v1, v0, v2}, Landroid/widget/Toast;->makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;\n",
                    "    move-result-object v0\n",
                    "    invoke-virtual {v0}, Landroid/widget/Toast;->show()V\n",
                    "    if-eqz p2, :cond_55\n",
                    "    invoke-static {}, Lorg/telegram/abhi/Hook;->hook()V\n",
                    "    goto :goto_58\n",
                    "    :cond_55\n",
                    "    invoke-static {}, Lorg/telegram/abhi/Hook;->unhook()V\n",
                    "    :goto_58\n",
                    "    return-void\n"
                ])
            if ".end method" in line:
                in_method = False
        else:
            new_lines.append(line)

    write_lines(file_path, new_lines)
    log_info("Injected toggle logic into setTextAndCheck2")


def _inject_prefs_to_oncreate(file_path: Path) -> None:
    lines = read_lines(file_path)
    new_lines = []
    in_method = False
    found = False
    codes = [
        "    sget-object v0, Lorg/telegram/messenger/ApplicationLoader;->applicationContext:Landroid/content/Context;\n",
        '    const-string v1, "mainconfig"\n',
        "    const/4 v2, 0x0\n",
        "    invoke-virtual {v0, v1, v2}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;\n",
        "    move-result-object v0\n",
        '    const-string v1, "candelMessages"\n',
        "    const/4 v2, 0x0\n",
        "    invoke-interface {v0, v1, v2}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z\n",
        "    move-result v0\n",
        "    sput-boolean v0, Lorg/telegram/abhi/Hook;->candelMessages:Z\n"
    ]

    for line in lines:
        if ".method protected onCreate" in line or ".method public onCreate" in line:
            in_method = True
            found = True
        if in_method and ".locals" in line:
            new_lines.append(line)
            new_lines.extend(codes)
            continue
        new_lines.append(line)

    if not found:
        log_warn("onCreate method not found in LaunchActivity")
        return

    write_lines(file_path, new_lines)
    log_info("Injected shared preferences into onCreate")


def modify_isPremium_stories(file_path: Path) -> None:
    code1 = [
        ".method private isPremium(J)Z\n",
        "    .locals 1\n",
        "    const/4 p1, 0x1\n",
        "    return p1\n",
        ".end method\n"
    ]
    code2 = [
        ".method public final isPremium(J)Z\n",
        "    .locals 1\n",
        "    const/4 p1, 0x1\n",
        "    return p1\n",
        ".end method\n"
    ]
    try:
        modify_method(file_path, "private isPremium(J)Z", code1)
    except NoMethodFoundError:
        try:
            modify_method(file_path, "public final isPremium(J)Z", code2)
        except NoMethodFoundError:
            log_warn("No isPremium(J)Z method found in StoriesController")


def modify_getCertificateSHA256Fingerprint(file_path: Path) -> None:
    code = [
        ".method public static getCertificateSHA256Fingerprint()Ljava/lang/String;\n",
        "    .locals 1\n",
        '    const-string v0, "49C1522548EBACD46CE322B6FD47F6092BB745D0F88082145CAF35E14DCC38E1"\n',
        "    return-object v0\n",
        ".end method\n"
    ]
    try:
        modify_method(file_path, "public static getCertificateSHA256Fingerprint()Ljava/lang/String;", code)
    except NoMethodFoundError as e:
        log_warn(str(e))


def modify_forcePremium(file_path: Path) -> None:
    code = [
        ".method static synthetic access$3000(Lorg/telegram/ui/PremiumPreviewFragment;)Z\n",
        "    .locals 0\n",
        "    const/4 p0, 0x1\n",
        "    return p0\n",
        ".end method\n"
    ]
    try:
        modify_method(file_path, "static synthetic access$3000(Lorg/telegram/ui/PremiumPreviewFragment;)Z", code)
    except NoMethodFoundError as e:
        log_warn(str(e))


def modify_markStories_method(file_path: Path) -> None:
    code1 = [
        ".method public markStoryAsRead(Lorg/telegram/tgnet/tl/TL_stories$PeerStories;Lorg/telegram/tgnet/tl/TL_stories$StoryItem;Z)Z\n",
        "    .locals 1\n",
        "    const/4 v0, 0x0\n",
        "    return v0\n",
        ".end method\n"
    ]
    code2 = [
        ".method public markStoryAsRead(JLorg/telegram/tgnet/tl/TL_stories$StoryItem;)Z\n",
        "    .locals 2\n",
        "    const/4 p1, 0x0\n",
        "    return p1\n",
        ".end method\n"
    ]
    try:
        modify_method(file_path, "public markStoryAsRead(Lorg/telegram/tgnet/tl/TL_stories$PeerStories;Lorg/telegram/tgnet/tl/TL_stories$StoryItem;Z)Z", code1)
    except NoMethodFoundError as e:
        log_warn(str(e))
    try:
        modify_method(file_path, "public markStoryAsRead(JLorg/telegram/tgnet/tl/TL_stories$StoryItem;)Z", code2)
    except NoMethodFoundError as e:
        log_warn(str(e))


def modify_isPremiumFeatureAvailable_method(file_path: Path, method_name: str) -> None:
    lines = read_lines(file_path)
    new_lines = []
    in_method = False
    found = False

    for line in lines:
        if f".method {method_name}" in line:
            in_method = True
            found = True
        if in_method and "const/4 v1, 0x0" in line:
            new_lines.append("    const/4 v1, 0x1\n")
            continue
        new_lines.append(line)
        if in_method and ".end method" in line:
            in_method = False

    if found:
        write_lines(file_path, new_lines)
        log_info(f"Patched {method_name} → return true")
    else:
        log_warn(f"Method {method_name} not found")


def modify_updateParams_method(file_path: Path, method_name: str) -> None:
    lines = read_lines(file_path)
    new_lines = []
    in_method = False
    found = False

    for line in lines:
        if f".method {method_name}" in line:
            in_method = True
            found = True
        if in_method:
            if "const/high16 v0, 0x20000" in line:
                new_lines.append("    const/high16 v0, 0x80000\n")
            elif "const/4 v0, 0x4" in line:
                new_lines.append("    const/16 v0, 0x8\n")
            else:
                new_lines.append(line)
        else:
            new_lines.append(line)

    if found:
        write_lines(file_path, new_lines)
        log_info("Updated download speed params")
    else:
        log_warn(f"Method {method_name} not found")


def modify_isChatNoForwards(file_path: Path) -> None:
    code1 = [
        ".method public isChatNoForwards(J)Z\n",
        "    .registers 3\n",
        "    const/4 p1, 0x0\n",
        "    return p1\n",
        ".end method\n"
    ]
    code2 = [
        ".method public isChatNoForwards(Lorg/telegram/tgnet/TLRPC$Chat;)Z\n",
        "    .registers 4\n",
        "    const/4 p1, 0x0\n",
        "    return p1\n",
        ".end method\n"
    ]
    try:
        modify_method(file_path, "public isChatNoForwards(J)Z", code1)
    except NoMethodFoundError as e:
        log_warn(str(e))
    try:
        modify_method(file_path, "public isChatNoForwards(Lorg/telegram/tgnet/TLRPC$Chat;)Z", code2)
    except NoMethodFoundError as e:
        log_warn(str(e))


def modify_checkCanOpenChat(file_path: Path) -> None:
    for sig in [
        "public checkCanOpenChat(Landroid/os/Bundle;Lorg/telegram/ui/ActionBar/BaseFragment;)Z",
        "public checkCanOpenChat(Landroid/os/Bundle;Lorg/telegram/ui/ActionBar/BaseFragment;Lorg/telegram/messenger/MessageObject;)Z",
        "public checkCanOpenChat(Landroid/os/Bundle;Lorg/telegram/ui/ActionBar/BaseFragment;Lorg/telegram/messenger/MessageObject;Lorg/telegram/messenger/browser/Browser$Progress;)Z"
    ]:
        code = [
            f".method {sig}\n",
            "    .registers 5\n",
            "    const/4 p1, 0x1\n",
            "    return p1\n",
            ".end method\n"
        ]
        try:
            modify_method(file_path, sig, code)
        except NoMethodFoundError:
            pass


def modify_is_sponsored_method(file_path: Path) -> None:
    code = [
        ".method public isSponsored()Z\n",
        "    .locals 2\n",
        "    const/4 v0, 0x0\n",
        "    return v0\n",
        ".end method\n"
    ]
    try:
        modify_method(file_path, "public isSponsored()Z", code)
    except NoMethodFoundError as e:
        log_warn(str(e))


def modify_is_sponsored_dis_method(file_path: Path) -> None:
    code = [
        ".method public isSponsoredDisabled()Z\n",
        "    .locals 2\n",
        "    const/4 v0, 0x1\n",
        "    return v0\n",
        ".end method\n"
    ]
    try:
        modify_method(file_path, "public isSponsoredDisabled()Z", code)
    except NoMethodFoundError as e:
        log_warn(str(e))


def modify_is_proxy_sponsored_method(file_path: Path) -> None:
    code = [
        ".method private checkPromoInfoInternal(Z)V\n",
        "    .locals 2\n",
        "    return-void\n",
        ".end method\n"
    ]
    try:
        modify_method(file_path, "private checkPromoInfoInternal(Z)V", code)
    except NoMethodFoundError as e:
        log_warn(str(e))


def modify_secret_media_methods(file_path: Path) -> None:
    lines = read_lines(file_path)
    new_lines = []
    in_method = False
    method_name = ""
    patched = {name: False for name in [
        "public getSecretTimeLeft()I",
        "public isSecretMedia()Z",
        "public static isSecretPhotoOrVideo(Lorg/telegram/tgnet/TLRPC$Message;)Z",
        "public static isSecretMedia(Lorg/telegram/tgnet/TLRPC$Message;)Z"
    ]}

    replacements = {
        "public isSecretMedia()Z": [
            ".method public isSecretMedia()Z\n",
            "    .locals 5\n",
            "    iget-object v0, p0, Lorg/telegram/messenger/MessageObject;->messageOwner:Lorg/telegram/tgnet/TLRPC$Message;\n",
            "    instance-of v1, v0, Lorg/telegram/tgnet/TLRPC$TL_message_secret;\n",
            "    const/4 v3, 0x0\n",
            "    return v3\n",
            ".end method\n"
        ],
        "public static isSecretPhotoOrVideo(Lorg/telegram/tgnet/TLRPC$Message;)Z": [
            ".method public static isSecretPhotoOrVideo(Lorg/telegram/tgnet/TLRPC$Message;)Z\n",
            "    .locals 4\n",
            "    instance-of v0, p0, Lorg/telegram/tgnet/TLRPC$TL_message_secret;\n",
            "    const/4 v2, 0x0\n",
            "    return v2\n",
            ".end method\n"
        ],
        "public static isSecretMedia(Lorg/telegram/tgnet/TLRPC$Message;)Z": [
            ".method public static isSecretMedia(Lorg/telegram/tgnet/TLRPC$Message;)Z\n",
            "    .locals 4\n",
            "    instance-of v0, p0, Lorg/telegram/tgnet/TLRPC$TL_message_secret;\n",
            "    const/4 v2, 0x0\n",
            "    return v2\n",
            ".end method\n"
        ]
    }

    for line in lines:
        sig_match = None
        for sig in patched:
            if sig in line:
                sig_match = sig
                break
        if sig_match:
            in_method = True
            method_name = sig_match
            patched[sig_match] = True
            if sig_match == "public getSecretTimeLeft()I":
                new_lines.append(line)
            else:
                new_lines.extend(replacements[sig_match])
            continue
        if in_method:
            if method_name == "public getSecretTimeLeft()I" and "const/4 v1, 0x0" in line:
                new_lines.append("    const/4 v1, 0x1\n")
            elif ".end method" in line:
                in_method = False
            else:
                new_lines.append(line)
        else:
            new_lines.append(line)

    if all(patched.values()):
        write_lines(file_path, new_lines)
        log_info("Secret media methods patched")
    else:
        log_warn("Some secret media methods not found")


# === Main Logic ===

def run_patch(name: str, func: Callable, root_dir: Path, target: str, *args) -> None:
    path = find_smali_file(root_dir, target)
    if not path:
        log_warn(f"{target} not found")
        return
    log_step(f"Applying: {name}")
    func(path, *args) if args else func(path)


def main(selected: Optional[str] = None, root_dir_str: str = "Telegram") -> None:
    root_dir = Path(root_dir_str).resolve()
    if not root_dir.exists():
        log_error(f"Directory not found: {root_dir}")
        sys.exit(1)

    patches: Dict[str, Tuple[str, Callable]] = {
        "0": ("Apply all patches [Except Anti Delete]", lambda: apply_all(root_dir, exclude=["0", "00", "17"])),
        "00": ("Apply all patches [Including Anti Delete]", lambda: apply_all(root_dir, exclude=["0", "00"])),
        "1": ("Disable Signature Verification (Critical)", lambda: run_patch("Sig Check", modify_getCertificateSHA256Fingerprint, root_dir, "AndroidUtilities.smali")),
        "2": ("Make isPremium() → true", lambda: run_patch("isPremium", modify_isPremium, root_dir, "UserConfig.smali")),
        "3": ("Stories: isPremium(J) → true", lambda: run_patch("Stories Premium", modify_isPremium_stories, root_dir, "StoriesController.smali")),
        "4": ("Force Premium UI", lambda: run_patch("forcePremium", modify_forcePremium, root_dir, "PremiumPreviewFragment.smali")),
        "5": ("Disable Mark Stories as Read", lambda: run_patch("Mark Stories", modify_markStories_method, root_dir, "StoriesController.smali")),
        "6": ("Unlock Premium Features", lambda: (
            run_patch("Premium Feature", modify_isPremiumFeatureAvailable_method, root_dir, "MessagesController.smali", "private isPremiumFeatureAvailable(I)Z"),
            run_patch("Premium Feature", modify_isPremiumFeatureAvailable_method, root_dir, "MessagesController.smali", "public final isPremiumFeatureAvailable(I)Z")
        )),
        "7": ("Boost Download Speed", lambda: run_patch("Speed Boost", modify_updateParams_method, root_dir, "DownloadController.smali", "private updateParams()V")),
        "8": ("Save Media from Restricted", lambda: run_patch("NoForwards", modify_isChatNoForwards, root_dir, "MessagesController.smali")),
        "9": ("Access Banned Chats", lambda: run_patch("Banned Chats", modify_checkCanOpenChat, root_dir, "MessagesController.smali")),
        "10": ("Banned Chats (Alt)", lambda: apply_isRestrictedMessage(root_dir)),
        "11": ("Save Media Anywhere", lambda: apply_enableSavingMedia(root_dir)),
        "12": ("Unlock Premium-Locked", lambda: apply_premiumLocked(root_dir)),
        "13": ("Enable Screenshots", lambda: (
            apply_EnableScreenshots(root_dir),
            apply_EnableScreenshots2(root_dir),
            apply_EnableScreenshots3(root_dir)
        )),
        "14": ("Hide Sponsored", lambda: run_patch("Sponsored", modify_is_sponsored_method, root_dir, "MessageObject.smali")),
        "15": ("Remove Promo Channels", lambda: run_patch("Promo", modify_is_proxy_sponsored_method, root_dir, "MessagesController.smali")),
        "16": ("View Secret Media", lambda: run_patch("Secret Media", modify_secret_media_methods, root_dir, "MessageObject.smali")),
        "17": ("Anti Message Delete", lambda: run_patch("Anti Delete", modify_markMessagesAsDeleted, root_dir, "MessagesStorage.smali")),
        "18": ("Hide Sponsored Banner", lambda: run_patch("Sponsored Disabled", modify_is_sponsored_dis_method, root_dir, "MessagesController.smali")),
    }

    if selected:
        selected_patches = [selected]
    else:
        print(f"{BLUE}Available Patches:{NC}")
        for k, (desc, _) in patches.items():
            print(f"{k:>2}: {desc}")
        selected_patches = input(f"\nEnter patch numbers (comma-separated): ").strip().split(",")

    for patch in (p.strip() for p in selected_patches):
        if patch in patches:
            patches[patch][1]()
        else:
            log_error(f"Invalid patch: {patch}")


def apply_all(root_dir: Path, exclude: List[str]) -> None:
    for k, (_, func) in main.__globals__["patches"].items():
        if k not in exclude:
            func()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Telegram Smali Patcher", prog="tgpatcher")
    parser.add_argument("--normal", action="store_true", help="Apply normal patches")
    parser.add_argument("--anti", action="store_true", help="Apply all patches including anti-delete")
    parser.add_argument("--dir", default="Telegram", help="Decompiled app directory")

    try:
        args = parser.parse_args()
        if args.normal:
            main("0", args.dir)
        elif args.anti:
            main("00", args.dir)
        else:
            main(None, args.dir)
    except KeyboardInterrupt:
        log_error("Script interrupted by user.")
        sys.exit(1)
    except Exception as e:
        log_error(f"Unexpected error: {e}")
        sys.exit(1)
