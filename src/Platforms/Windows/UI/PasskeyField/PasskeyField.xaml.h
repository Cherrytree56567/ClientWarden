#pragma once

#include "PasskeyField.g.h"

namespace winrt::WindowsUI::implementation
{
    struct PasskeyField : PasskeyFieldT<PasskeyField>
    {
        PasskeyField()
        {
            // Xaml objects should not call InitializeComponent during construction.
            // See https://github.com/microsoft/cppwinrt/tree/master/nuget#initializecomponent
        }

        winrt::hstring Title();
        void Title(winrt::hstring const& value);

        winrt::hstring Value();
        void Value(winrt::hstring const& value);
    };
}

namespace winrt::WindowsUI::factory_implementation
{
    struct PasskeyField : PasskeyFieldT<PasskeyField, implementation::PasskeyField>
    {
    };
}
