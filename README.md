# Cyber Defence Kit Documentation

Welcome to the **Cyber Defence Kit Documentation** repository! This project provides comprehensive, well-structured documentation for the Cyber Defence Kit, designed to assist users in deploying and utilising various tools for security operations and incident response.

## Built With

This documentation is built using [**MkDocs Material**](https://squidfunk.github.io/mkdocs-material/), a powerful and customisable static site generator that brings documentation to life with:

- A modern, responsive design
- Easy-to-use Markdown syntax
- Advanced features like search, versioning, and integrations

## Features

- **Clear Structure**: Organised sections for easy navigation and understanding.
- **Searchable**: Quickly find the information you need.
- **Customisable**: Built with MkDocs Material, allowing for future enhancements and theming.
- **Interactive Elements**: Supports embedding code blocks, diagrams, and more.

## Getting Started

To view the documentation locally, follow these steps:

1. Clone this repository:
    
    ```bash
    git clone https://github.com/cyberdefencekit/documentation.git
    cd documentation
    ```
    
2. Install the required dependencies:
    
    ```bash
    pip install mkdocs-material
    ```
    
3. Install the missing dependencies:
    
    ```bash
    pip install "mkdocs-material[imaging]"
    pip install mkdocs-glightbox
    ```
    
4. Serve the documentation locally:
    
    ```bash
    mkdocs serve
    ```
    
5. Open your browser and navigate to `http://127.0.0.1:8000`.

### Installation Notes

If the `mkdocs` command is not available after installing `mkdocs-material`, it’s likely due to the following reasons:

1. The `mkdocs` executable is installed in the user's local `~/.local/bin/` directory, which may not be included in your system's `PATH` environment variable.
2. Without the correct `PATH` configuration, the terminal cannot locate the `mkdocs` executable.

To resolve this, you can either:

- Add `~/.local/bin/` to your `PATH`:
    
    ```bash
    echo 'export PATH=$PATH:~/.local/bin' >> ~/.bashrc
    source ~/.bashrc
    ```
    
- Install `mkdocs` system-wide using your package manager:
    
    ```bash
    sudo apt install mkdocs
    ```
    

## Licence

Cyber Defence Kit documentation is created by **Joseph Jee** and licensed under the **Creative Commons Attribution 4.0 International (CC BY 4.0) License**.  
You are free to share and adapt the content with proper attribution.  
[Read more about this license](https://creativecommons.org/licenses/by/4.0/).
[Visit my website](https://josephjee.com)
