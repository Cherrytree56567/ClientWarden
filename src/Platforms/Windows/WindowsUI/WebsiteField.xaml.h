#pragma once

#include "WebsiteField.g.h"

namespace winrt::WindowsUI::implementation
{
    struct WebsiteField : WebsiteFieldT<WebsiteField>
    {
        WebsiteField()
        {
            // Xaml objects should not call InitializeComponent during construction.
            // See https://github.com/microsoft/cppwinrt/tree/master/nuget#initializecomponent
        }

        winrt::hstring Title();
        void Title(winrt::hstring const& value);
        Microsoft::UI::Xaml::Controls::UIElementCollection Value();
        void Value(Microsoft::UI::Xaml::Controls::UIElementCollection value);
    };
}

namespace winrt::WindowsUI::factory_implementation
{
    struct WebsiteField : WebsiteFieldT<WebsiteField, implementation::WebsiteField>
    {
    };
}
