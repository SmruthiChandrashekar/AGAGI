"""
tools/project_detector.py
-------------------------
Detects programming language, package manager, build system,
and test command from manifest files in a repository.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field

from core.logging import get_logger

logger = get_logger(__name__)


class ProjectInfo(BaseModel):
    """Information discovered by inspecting repository manifests."""

    primary_language: str = Field(default="unknown", description="Primary detected language")
    all_languages: list[str] = Field(default_factory=list, description="All detected languages")
    build_system: str | None = Field(default=None, description="Build system / package manager")
    test_command: str | None = Field(default=None, description="Default test command")
    manifest_files: list[str] = Field(default_factory=list, description="Relevant files found")

    @property
    def language(self) -> str:
        return self.primary_language


def detect_project(repo_path: Path | str) -> ProjectInfo:
    """
    Inspect repo_path for manifest files to determine language, build system,
    and test invocation command.
    """
    root = Path(repo_path).resolve()
    manifests: list[str] = []
    languages: set[str] = set()

    build_system: str | None = None
    test_command: str | None = None

    # 1. Python Detection
    pyproject = root / "pyproject.toml"
    requirements = root / "requirements.txt"
    setup_py = root / "setup.py"
    pipfile = root / "Pipfile"

    if pyproject.is_file() or requirements.is_file() or setup_py.is_file() or pipfile.is_file():
        languages.add("python")
        if pyproject.is_file():
            manifests.append("pyproject.toml")
            content = pyproject.read_text(encoding="utf-8", errors="ignore")
            if "poetry" in content:
                build_system = "poetry"
                test_command = "poetry run pytest"
            elif "flit" in content:
                build_system = "flit"
                test_command = "pytest"
            elif "hatch" in content:
                build_system = "hatch"
                test_command = "hatch test"
            else:
                build_system = "pip"
                test_command = "pytest"
        elif pipfile.is_file():
            manifests.append("Pipfile")
            build_system = "pipenv"
            test_command = "pipenv run pytest"
        elif requirements.is_file():
            manifests.append("requirements.txt")
            build_system = "pip"
            test_command = "pytest"
        elif setup_py.is_file():
            manifests.append("setup.py")
            build_system = "pip"
            test_command = "pytest"
    else:
        # Fallback Python detection from source and test files
        py_files = [
            f for f in root.glob("*.py")
            if not f.name.startswith(".") and f.name != "__pycache__"
        ]
        tests_dir = root / "tests"
        if tests_dir.is_dir():
            py_files.extend([f for f in tests_dir.glob("*.py") if not f.name.startswith(".")])
        if py_files:
            languages.add("python")
            build_system = build_system or "python"
            has_tests = any(
                f.name.startswith("test_") or f.name.endswith("_test.py") or "test" in f.name.lower()
                for f in py_files
            )
            if has_tests:
                test_command = "pytest"

    # 2. Node / JavaScript / TypeScript Detection
    pkg_json = root / "package.json"
    if pkg_json.is_file():
        languages.add("javascript")
        manifests.append("package.json")
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8", errors="ignore"))
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}

            if (
                "typescript" in deps
                or (root / "tsconfig.json").is_file()
                or any(root.glob("src/**/*.ts"))
            ):
                languages.add("typescript")

            if (root / "pnpm-lock.yaml").is_file():
                build_system = build_system or "pnpm"
                manifests.append("pnpm-lock.yaml")
                test_command = test_command or "pnpm test"
            elif (root / "yarn.lock").is_file():
                build_system = build_system or "yarn"
                manifests.append("yarn.lock")
                test_command = test_command or "yarn test"
            else:
                build_system = build_system or "npm"
                test_command = test_command or "npm test"
        except Exception:
            build_system = build_system or "npm"
            test_command = test_command or "npm test"

    # 3. Java (Maven / Gradle)
    pom_xml = root / "pom.xml"
    build_gradle = root / "build.gradle"
    build_gradle_kts = root / "build.gradle.kts"
    if pom_xml.is_file():
        languages.add("java")
        manifests.append("pom.xml")
        build_system = build_system or "maven"
        test_command = test_command or "mvn test"
    elif build_gradle.is_file() or build_gradle_kts.is_file():
        languages.add("java")
        manifest_name = "build.gradle" if build_gradle.is_file() else "build.gradle.kts"
        manifests.append(manifest_name)
        build_system = build_system or "gradle"
        test_command = (
            test_command or ("./gradlew test" if (root / "gradlew").is_file() else "gradle test")
        )

    # 4. Go
    go_mod = root / "go.mod"
    if go_mod.is_file():
        languages.add("go")
        manifests.append("go.mod")
        build_system = build_system or "go"
        test_command = test_command or "go test ./..."

    # 5. Rust
    cargo_toml = root / "Cargo.toml"
    if cargo_toml.is_file():
        languages.add("rust")
        manifests.append("Cargo.toml")
        build_system = build_system or "cargo"
        test_command = test_command or "cargo test"

    # Determine primary language
    primary_lang = "unknown"
    if "python" in languages:
        primary_lang = "python"
    elif "typescript" in languages:
        primary_lang = "typescript"
    elif "javascript" in languages:
        primary_lang = "javascript"
    elif "java" in languages:
        primary_lang = "java"
    elif "go" in languages:
        primary_lang = "go"
    elif "rust" in languages:
        primary_lang = "rust"
    elif languages:
        primary_lang = sorted(languages)[0]

    return ProjectInfo(
        primary_language=primary_lang,
        all_languages=sorted(languages),
        build_system=build_system,
        test_command=test_command,
        manifest_files=manifests,
    )
