import re
from collections import defaultdict
from packaging import version
import matplotlib.pyplot as plt
import pandas as pd

vulnerable_themes = {
    "xstore": [(None, "9.3")],
    "travelscape": [(None, "1.0.3")],
    "zox-news": [(None, "3.17.0")],
    "listingpro": [(None, "2.6.1")],
}

vulnerable_plugins = {
    "frontend-login-and-registration-blocks": [(None, "1.0.7")],
    "depicter": [(None, "3.6.1")],
    "learnpress": [(None, "4.2.7")],
    "suretriggers": [(None, "1.0.82")],
    "k-elements": [(None, "5.4.0")],
    "litespeed-cache": [(None, "6.5.0.1"), ("1.9", "6.3.0.1")],
    "vikbooking": [(None, "1.6.8")],
}

def parse_file(file_path):
    websites = []
    with open(file_path, "r", encoding="utf-8") as file:
        content = file.read()

    # Split the content based on the page sections
    sections = content.split("*******")
    
    for section in sections:
        if "Page URL:" in section:
            # Extract the URL
            url_match = re.search(r"Page URL: (https?://[^\s]+)", section)
            if url_match:
                url = url_match.group(1)

                # Extract the theme
                theme_match = re.search(r"Theme:\s*(\S+)", section)
                theme = theme_match.group(1) if theme_match else None

                # Extract plugins and their versions
                plugins_match = re.search(r"Plugins: ([^\n]+)", section)
                plugins = plugins_match.group(1) if plugins_match else ""
                plugin_list = plugins.split(", ") if plugins else []

                website_info = {"url": url, "theme": theme, "plugins": plugin_list}
                websites.append(website_info)

    return websites

def version_is_exact(version_str, exact_version):
    """
    Compares a version string to an exact version.
    """
    try:
        current_version = version.parse(version_str)
        return current_version == version.parse(exact_version)
    except ValueError:
        return False

def version_in_range(version_str, min_version, max_version):
    """
    Compares a version string to a min and max version.
    """
    try:
        current_version = version.parse(version_str)
        if min_version is None and max_version is None:
            return True
        if min_version is None:
            return current_version <= version.parse(max_version)
        if max_version is None:
            return current_version >= version.parse(min_version)
        return version.parse(min_version) <= current_version <= version.parse(max_version)
    except ValueError:
        return False

def is_valid_version_string(s):
    try:
        # Accepts only if s is a valid version (not just a number/hash)
        v = version.parse(s)
        # packaging.version.Version will parse numbers like '1746468293', but we want to exclude those
        # Accept only if it contains at least one dot (e.g., 1.2, 3.6.1, v1.0.3)
        return '.' in s or s.startswith('v')
    except Exception:
        return False

def summarize_vulnerabilities(websites):
    theme_usage = defaultdict(list)
    plugin_usage = defaultdict(list)
    theme_no_version_usage = defaultdict(list)
    plugin_no_version_usage = defaultdict(list)

    for website in websites:
        theme = website["theme"]
        plugins = website["plugins"]
        url = website["url"]

        # Track vulnerable themes with exact version or version range match
        if theme:
            theme_info_split = theme.split("@")
            theme_name = theme_info_split[0]
            theme_version = theme_info_split[1] if len(theme_info_split) > 1 else None
            if theme_name in vulnerable_themes:
                for theme_version_data in vulnerable_themes[theme_name]:
                    if theme_version and is_valid_version_string(theme_version):
                        if isinstance(theme_version_data, tuple):
                            min_version, max_version = theme_version_data
                            if version_in_range(theme_version, min_version, max_version):
                                theme_usage[(theme_name, theme_version_data)].append({"url": url, "version": theme_version})
                        else:
                            if version_is_exact(theme_version, theme_version_data):
                                theme_usage[(theme_name, theme_version_data)].append({"url": url, "version": theme_version})
                    else:
                        theme_no_version_usage[(theme_name, theme_version_data)].append({"url": url})

        # Track vulnerable plugins with exact version or version range match
        for plugin_info in plugins:
            plugin_info_split = plugin_info.split("@")
            plugin_name = plugin_info_split[0]
            plugin_version = plugin_info_split[1] if len(plugin_info_split) > 1 else None

            if plugin_name in vulnerable_plugins:
                for plugin_version_data in vulnerable_plugins[plugin_name]:
                    if plugin_version and is_valid_version_string(plugin_version):
                        if isinstance(plugin_version_data, tuple):
                            min_version, max_version = plugin_version_data
                            if version_in_range(plugin_version, min_version, max_version):
                                plugin_usage[(plugin_name, plugin_version_data)].append({"url": url, "version": plugin_version})
                        else:
                            if version_is_exact(plugin_version, plugin_version_data):
                                plugin_usage[(plugin_name, plugin_version_data)].append({"url": url, "version": plugin_version})
                    else:
                        plugin_no_version_usage[(plugin_name, plugin_version_data)].append({"url": url})

    return theme_usage, plugin_usage, theme_no_version_usage, plugin_no_version_usage

def print_summary(theme_usage, plugin_usage, theme_no_version_usage, plugin_no_version_usage):
    print("Vulnerable Themes Summary:")
    for (theme, version_info), websites in theme_usage.items():
        print(f"\nTheme: {theme} (Vulnerable Version/Range: {version_info})")
        print(f"  Total Websites: {len(websites)}")
        print(f"  Websites:")
        for website in websites:
            print(f"    - {website['url']} (Version: {website['version']})")
    if theme_no_version_usage:
        print("\nVulnerable Themes Without Version Info:")
        for (theme, version_info), websites in theme_no_version_usage.items():
            print(f"\nTheme: {theme} (Vulnerable Version/Range: {version_info})")
            print(f"  Total Websites: {len(websites)}")
            print(f"  Websites:")
            for website in websites:
                print(f"    - {website['url']}")
    print("\nVulnerable Plugins Summary:")
    for (plugin, version_info), websites in plugin_usage.items():
        print(f"\nPlugin: {plugin} (Vulnerable Version/Range: {version_info})")
        print(f"  Total Websites: {len(websites)}")
        print(f"  Websites:")
        for website in websites:
            print(f"    - {website['url']} (Version: {website['version']})")
    if plugin_no_version_usage:
        print("\nVulnerable Plugins Without Version Info:")
        for (plugin, version_info), websites in plugin_no_version_usage.items():
            print(f"\nPlugin: {plugin} (Vulnerable Version/Range: {version_info})")
            print(f"  Total Websites: {len(websites)}")
            print(f"  Websites:")
            for website in websites:
                print(f"    - {website['url']}")

def print_vulnerability_table(theme_usage, plugin_usage, theme_no_version_usage, plugin_no_version_usage):
    # Prepare data for themes: show all from vulnerable_themes, even if not found
    theme_rows = []
    for theme in vulnerable_themes.keys():
        for version_info in vulnerable_themes[theme]:
            vuln_count = len(theme_usage.get((theme, version_info), []))
            possible_vuln_count = len(theme_no_version_usage.get((theme, version_info), []))
            theme_rows.append({
                'Theme': theme,
                'Vulnerable': vuln_count,
                'Possibly Vulnerable (No Version)': possible_vuln_count,
                'Vulnerable Version/Range': version_info
            })
    theme_df = pd.DataFrame(theme_rows)
    if not theme_df.empty:
        print("\n=== Vulnerable Themes Table ===")
        print(theme_df.sort_values(by=['Vulnerable', 'Possibly Vulnerable (No Version)'], ascending=False).to_string(index=False))
    else:
        print("\nNo vulnerable themes found.")

    # Prepare data for plugins: show all from vulnerable_plugins, even if not found
    plugin_rows = []
    for plugin in vulnerable_plugins.keys():
        for version_info in vulnerable_plugins[plugin]:
            vuln_count = len(plugin_usage.get((plugin, version_info), []))
            possible_vuln_count = len(plugin_no_version_usage.get((plugin, version_info), []))
            plugin_rows.append({
                'Plugin': plugin,
                'Vulnerable': vuln_count,
                'Possibly Vulnerable (No Version)': possible_vuln_count,
                'Vulnerable Version/Range': version_info
            })
    plugin_df = pd.DataFrame(plugin_rows)
    if not plugin_df.empty:
        print("\n=== Vulnerable Plugins Table ===")
        print(plugin_df.sort_values(by=['Vulnerable', 'Possibly Vulnerable (No Version)'], ascending=False).to_string(index=False))
    else:
        print("\nNo vulnerable plugins found.")

def plot_vulnerabilities(theme_usage, plugin_usage, theme_no_version_usage, plugin_no_version_usage):
    # Bar plot for themes (with version and no version) by (theme, version/range)
    theme_counts = []
    for theme in vulnerable_themes.keys():
        for version_info in vulnerable_themes[theme]:
            vuln_count = len(theme_usage.get((theme, version_info), []))
            possible_vuln_count = len(theme_no_version_usage.get((theme, version_info), []))
            label = f"{theme}\n{version_info}"
            theme_counts.append({
                'label': label,
                'Vulnerable': vuln_count,
                'Possibly Vulnerable (No Version)': possible_vuln_count
            })
    theme_df = pd.DataFrame(theme_counts)
    if not theme_df.empty:
        theme_df = theme_df.sort_values(by=['Vulnerable', 'Possibly Vulnerable (No Version)'], ascending=False)
        theme_df.set_index('label', inplace=True)
        theme_df[['Vulnerable', 'Possibly Vulnerable (No Version)']].plot(
            kind='bar', stacked=False, figsize=(12, 5), color=['#3498db', '#e67e22']
        )
        plt.title('Vulnerable Themes (by version/range)')
        plt.ylabel('Number of Websites')
        plt.xlabel('Theme and Vulnerable Version/Range')
        plt.xticks(rotation=20, ha='right')
        plt.tight_layout()
        plt.show()

    # Bar plot for plugins (with version and no version) by (plugin, version/range)
    plugin_counts = []
    for plugin in vulnerable_plugins.keys():
        for version_info in vulnerable_plugins[plugin]:
            vuln_count = len(plugin_usage.get((plugin, version_info), []))
            possible_vuln_count = len(plugin_no_version_usage.get((plugin, version_info), []))
            label = f"{plugin}\n{version_info}"
            plugin_counts.append({
                'label': label,
                'Vulnerable': vuln_count,
                'Possibly Vulnerable (No Version)': possible_vuln_count
            })
    plugin_df = pd.DataFrame(plugin_counts)
    if not plugin_df.empty:
        plugin_df = plugin_df.sort_values(by=['Vulnerable', 'Possibly Vulnerable (No Version)'], ascending=False)
        plugin_df.set_index('label', inplace=True)
        plugin_df[['Vulnerable', 'Possibly Vulnerable (No Version)']].plot(
            kind='bar', stacked=False, figsize=(12, 5), color=['#e74c3c', '#f1c40f']
        )
        plt.title('Vulnerable Plugins (by version/range)')
        plt.ylabel('Number of Websites')
        plt.xlabel('Plugin and Vulnerable Version/Range')
        plt.xticks(rotation=20, ha='right')
        plt.tight_layout()
        plt.show()
    # Table for themes without version
    if theme_no_version_usage:
        print('\nThemes Without Version Info (Table):')
        for theme, sites in theme_no_version_usage.items():
            df = pd.DataFrame(sites)
            print(f'\nTheme: {theme}')
            print(df)
    # Table for plugins without version
    if plugin_no_version_usage:
        print('\nPlugins Without Version Info (Table):')
        for plugin, sites in plugin_no_version_usage.items():
            df = pd.DataFrame(sites)
            print(f'\nPlugin: {plugin}')
            print(df)

file_path = "../important-results/results-wordpress-top1m"
websites = parse_file(file_path)
theme_usage, plugin_usage, theme_no_version_usage, plugin_no_version_usage = summarize_vulnerabilities(websites)
print_summary(theme_usage, plugin_usage, theme_no_version_usage, plugin_no_version_usage)
print_vulnerability_table(theme_usage, plugin_usage, theme_no_version_usage, plugin_no_version_usage)
plot_vulnerabilities(theme_usage, plugin_usage, theme_no_version_usage, plugin_no_version_usage)
