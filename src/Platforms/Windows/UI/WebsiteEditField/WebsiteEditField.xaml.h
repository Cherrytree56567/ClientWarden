#pragma once

#include "WebsiteEditField.g.h"

namespace winrt::WindowsUI::implementation
{
    struct WebsiteEditField : WebsiteEditFieldT<WebsiteEditField>
    {
        WebsiteEditField()
        {
            // Xaml objects should not call InitializeComponent during construction.
            // See https://github.com/microsoft/cppwinrt/tree/master/nuget#initializecomponent
        }

        winrt::hstring Title();
        void Title(winrt::hstring const& value);

        void AddField(winrt::hstring Text);
        Windows::Foundation::Collections::IVector<winrt::hstring> GetFields();

        void AddButton_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e);
    };
}

namespace winrt::WindowsUI::factory_implementation
{
    struct WebsiteEditField : WebsiteEditFieldT<WebsiteEditField, implementation::WebsiteEditField>
    {
    };
}
