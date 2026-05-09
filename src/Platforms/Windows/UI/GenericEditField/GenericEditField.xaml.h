#pragma once

#include "GenericEditField.g.h"

namespace winrt::WindowsUI::implementation
{
    struct GenericEditField : GenericEditFieldT<GenericEditField>
    {
        GenericEditField()
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
    struct GenericEditField : GenericEditFieldT<GenericEditField, implementation::GenericEditField>
    {
    };
}
