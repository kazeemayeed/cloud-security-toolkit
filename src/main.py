#!/usr/bin/env python3
"""
Cloud Infrastructure Security Toolkit
Main CLI entry point
"""

import click
import sys
import json
from pathlib import Path
from typing import Optional

from core.analyzer import SecurityAnalyzer
from utils.logger import setup_logger
from utils.helpers import load_config, save_report


@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option(
    "--config", "-c", type=click.Path(exists=True), help="Configuration file path"
)
@click.pass_context
def cli(ctx, verbose, config):
    """Cloud Infrastructure Security Hardening as Code Toolkit"""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    ctx.obj["config_path"] = config
    setup_logger(verbose)


@cli.command()
@click.option(
    "--path",
    "-p",
    required=True,
    type=click.Path(exists=True),
    help="Path to infrastructure files or directory",
)
@click.option(
    "--format",
    "-f",
    type=click.Choice(["terraform", "cloudformation", "arm"]),
    required=True,
    help="Infrastructure as Code format",
)
@click.option("--output", "-o", type=click.Path(), help="Output report file path")
@click.option(
    "--severity",
    "-s",
    type=click.Choice(["low", "medium", "high", "critical"]),
    default="medium",
    help="Minimum severity level to report",
)
@click.option(
    "--cloud",
    "-cl",
    type=click.Choice(["aws", "azure", "gcp", "all"]),
    default="all",
    help="Cloud provider to analyze",
)
@click.pass_context
def analyze(ctx, path, format, output, severity, cloud):
    """Analyze infrastructure configurations for security issues"""
    try:
        config = load_config(ctx.obj.get("config_path"))
        analyzer = SecurityAnalyzer(config)

        click.echo(f"🔍 Analyzing {format} files in {path}...")

        results = analyzer.analyze_path(
            path=Path(path),
            format=format,
            cloud_provider=cloud,
            min_severity=severity,
        )

        # Display summary
        click.echo(f"\n📊 Analysis Results:")
        click.echo(f"   Files analyzed: {results['summary']['files_analyzed']}")
        click.echo(f"   Issues found: {results['summary']['total_issues']}")
        click.echo(f"   Critical: {results['summary']['critical']}")
        click.echo(f"   High: {results['summary']['high']}")
        click.echo(f"   Medium: {results['summary']['medium']}")
        click.echo(f"   Low: {results['summary']['low']}")

        # Save report if output specified
        if output:
            save_report(results, output)
            click.echo(f"📝 Report saved to {output}")

        # Exit with error code if critical issues found
        if results["summary"]["critical"] > 0:
            sys.exit(1)

    except Exception as e:
        click.echo(f"❌ Error during analysis: {str(e)}", err=True)
        sys.exit(1)


@cli.command()
@click.option(
    "--path",
    "-p",
    required=True,
    type=click.Path(exists=True),
    help="Path to infrastructure files or directory",
)
@click.option(
    "--format",
    "-f",
    type=click.Choice(["terraform", "cloudformation", "arm"]),
    required=True,
    help="Infrastructure as Code format",
)
@click.option("--fix", is_flag=True, help="Apply automatic fixes")
@click.option(
    "--backup", is_flag=True, default=True, help="Create backup before fixing"
)
@click.pass_context
def remediate(ctx, path, format, fix, backup):
    """Remediate security issues in infrastructure configurations"""
    try:
        config = load_config(ctx.obj.get("config_path"))
        analyzer = SecurityAnalyzer(config)

        click.echo(f"🔧 Analyzing and remediating {format} files in {path}...")

        results = analyzer.remediate_path(
            path=Path(path), format=format, apply_fixes=fix, create_backup=backup
        )

        click.echo(f"\n🔧 Remediation Results:")
        click.echo(f"   Issues found: {results['total_issues']}")
        click.echo(f"   Auto-fixable: {results['auto_fixable']}")
        click.echo(f"   Fixed: {results['fixed']}")
        click.echo(f"   Manual review needed: {results['manual_review']}")

    except Exception as e:
        click.echo(f"❌ Error during remediation: {str(e)}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    cli()
