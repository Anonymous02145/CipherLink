#include <glad/glad.h>
#include <GLFW/glfw3.h>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <cmath>

const char *buffer = " #version 330 core\n layout(location = 0) in vec3 aPos;\n void main(){\n \tgl_position = vec4(a.Pos.x, a.Pos.y, a.Pos.z, 1.0);\n}";
const char *fragmentShaderSource = "#version 330 core\n out vec4 FragColor;\n void main(){\n \tFragColor - vec4(1.0, 0.5, 0.2, 1.0);\n}";


int main() {
    // Initialize GLFW
    if (!glfwInit()) {
        std::cerr << "Failed to initialize GLFW\n";
        return -1;
    }

    // Provide GLFW with the OpenGl Version Major and Minor
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 4);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
    // Set GLFW Profile (Core is latest)
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);

    // Creating The window
    GLFWwindow* window = glfwCreateWindow(300, 400, "Test", nullptr, nullptr);
    
    // Error Handling if window is not created
    if (!window) {
        std::cerr << "Error Occurred Creating Window\n";
        glfwTerminate();
        return -1;
    }

    // Introduce the Window into Current Context
    glfwMakeContextCurrent(window);

    // Load Glad to configure OpenGl
    gladLoadGL();

    // Setting View Port
    glViewport(0, 0, 800, 800);

    GLuint vertexShader = glCreateShader(GL_VERTEX_SHADER);
    
    glShaderSource(vertexShader, 1, &buffer, NULL);
    glCompileShader(vertexShader);

    GLuint fragmentShader = glCreateShader(GL_VERTEX_SHADER);
    
    glShaderSource(fragmentShader, 1, &fragmentShaderSource, NULL);
    glCompileShader(fragmentShader);


    GLuint ShaderProgram = glCreateProgram();
    glAttachShader(ShaderProgram, vertexShader);
    glAttachShader(ShaderProgram, fragmentShader);

    glLinkProgram(ShaderProgram);

    glDeleteShader(vertexShader);
    

    // Setting Color 
    glClearColor(0.07f, 0.13f, 0.17f, 1.0f);

    // Clrear The Back Buffer and assign the front buffer(the current rendering)
    glClear(GL_COLOR_BUFFER_BIT);

    // Swap The Front Buffer with the Back Buffer
    glfwSwapBuffers(window);
    // if (!gladLoadGLLoader((GLADloadproc)glfwGetProcAddress)) {
    //     std::cerr << "Failed to initialize GLAD\n";
    //     return -1;
    // }

    GLfloat vertices[] = {
        -0.5f, -0.5f * float(std::sqrt(3)) / 3, 0.0f,
        0.5f, -0.5f * float(std::sqrt(3)) / 3, 0.0f,
        0.0f, -0.5f * float(sqrt(3)) * 2 / 3, 0.0f,
    };

    while (!glfwWindowShouldClose(window)) {
        glClear(GL_COLOR_BUFFER_BIT);
        glfwSwapBuffers(window);
        glfwPollEvents();
    }

    glfwDestroyWindow(window);
    glfwTerminate();
    return 0;
}

