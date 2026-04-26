#pragma once

#include "CheckboxField.g.h"

namespace winrt::WindowsUI::implementation
{
    struct CheckboxField : CheckboxFieldT<CheckboxField>
    {
        CheckboxField()
        {
            // Xaml objects should not call InitializeComponent during construction.
            // See https://github.com/microsoft/cppwinrt/tree/master/nuget#initializecomponent
        }

        winrt::hstring Title();
        void Title(winrt::hstring const& value);

        bool Value();
        void Value(bool value);
    };
}

namespace winrt::WindowsUI::factory_implementation
{
    struct CheckboxField : CheckboxFieldT<CheckboxField, implementation::CheckboxField>
    {
    };
}
